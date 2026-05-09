package Forensicator;
use strict;
use warnings;
use 5.014;

use DBI;
use Digest::SHA;
use Sys::Hostname ();
use JSON::PP ();
use Exporter 'import';

our $VERSION = '0.01';
use constant SCHEMA_VERSION => 1;

our @EXPORT_OK = qw(
    open_catalog init_catalog catalog_meta set_catalog_meta
    upsert_volume get_volume volumes
    sha512_file
    normalize_path is_case_insensitive_os
    default_hostname os_name
    json_decode json_encode jsonl_reader jsonl_writer
    SCHEMA_VERSION
);

sub os_name { $^O }

sub is_case_insensitive_os {
    my $os = shift // os_name();
    return $os =~ /^(MSWin32|cygwin|msys|darwin)$/ ? 1 : 0;
}

sub default_hostname {
    my $h = Sys::Hostname::hostname();
    $h =~ s/\..*$//;
    return $h;
}

sub normalize_path {
    my ($path, $os) = @_;
    $os //= os_name();
    my $n = $path;
    $n =~ tr{\\}{/};
    $n =~ s{/+}{/}g;
    $n =~ s{^\./}{};
    $n =~ s{/$}{} unless $n eq '/';
    $n = lc $n if is_case_insensitive_os($os);
    return $n;
}

sub sha512_file {
    my $path = shift;
    open my $fh, '<:raw', $path or return undef;
    my $sha = Digest::SHA->new(512);
    eval { $sha->addfile($fh); 1 } or do { close $fh; return undef };
    close $fh;
    return $sha->hexdigest;
}

sub open_catalog {
    my ($path, %opts) = @_;
    my $dbh = DBI->connect("dbi:SQLite:dbname=$path", '', '', {
        RaiseError     => 1,
        PrintError     => 0,
        AutoCommit     => 1,
        sqlite_unicode => 1,
    });
    unless ($opts{readonly}) {
        eval { $dbh->do('PRAGMA journal_mode = WAL'); 1 }
            or warn "[forensicator] WAL journal mode unavailable on this filesystem ($path); using rollback journal\n";
        eval { $dbh->do('PRAGMA synchronous = NORMAL'); 1 };
    }
    eval { $dbh->do('PRAGMA foreign_keys = ON'); 1 };
    eval { $dbh->do('PRAGMA cache_size = -200000'); 1 };

    my $ok = eval {
        my $has_meta = $dbh->selectrow_array(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='meta'"
        );
        if ($has_meta) {
            my $sv = catalog_meta($dbh, 'schema_version') // 0;
            die "catalog $path has schema version $sv, expected " . SCHEMA_VERSION . "\n"
                if $sv != SCHEMA_VERSION;
        }
        init_catalog($dbh, %opts) unless $opts{readonly};
        1;
    };
    unless ($ok) {
        my $err = $@;
        eval { $dbh->disconnect };
        if ($err =~ /disk I\/O error|database is locked|locking protocol/i) {
            die <<"MSG";
cannot open catalog $path: $err
This filesystem appears to have broken POSIX locking (SMB / NFS / exFAT /
some FUSE mounts). forensicator refuses to operate on such filesystems
because long-running scans corrupt SQLite there ("database disk image is
malformed"), and the previous nolock fallback caused real data loss.

Move the catalog to a local SSD/HDD with a normal filesystem (APFS / ext4
/ NTFS / HFS+) and re-run. The catalog records mount_point separately so
it can still find files on the original data volume, regardless of where
the SQLite file lives.
MSG
        }
        die "cannot open catalog $path: $err";
    }
    return $dbh;
}

sub init_catalog {
    my ($dbh, %opts) = @_;
    $dbh->do(<<'SQL');
CREATE TABLE IF NOT EXISTS meta (
  key   TEXT PRIMARY KEY,
  value TEXT
)
SQL
    $dbh->do(<<'SQL');
CREATE TABLE IF NOT EXISTS volumes (
  volume_id   INTEGER PRIMARY KEY AUTOINCREMENT,
  hostname    TEXT NOT NULL,
  volume      TEXT NOT NULL,
  mount_point TEXT,
  os          TEXT,
  scanned_at  INTEGER,
  UNIQUE(hostname, volume)
)
SQL
    $dbh->do(<<'SQL');
CREATE TABLE IF NOT EXISTS files (
  file_id    INTEGER PRIMARY KEY AUTOINCREMENT,
  volume_id  INTEGER NOT NULL REFERENCES volumes(volume_id) ON DELETE CASCADE,
  path       TEXT NOT NULL,
  path_norm  TEXT NOT NULL,
  size       INTEGER NOT NULL,
  mtime      INTEGER NOT NULL,
  sha512     TEXT,
  scanned_at INTEGER NOT NULL,
  UNIQUE(volume_id, path_norm)
)
SQL
    $dbh->do('CREATE INDEX IF NOT EXISTS idx_files_sha512 ON files(sha512) WHERE sha512 IS NOT NULL');
    $dbh->do('CREATE INDEX IF NOT EXISTS idx_files_size   ON files(size)');
    $dbh->do('CREATE INDEX IF NOT EXISTS idx_files_volume ON files(volume_id, path_norm)');

    set_catalog_meta($dbh, 'schema_version', SCHEMA_VERSION);
    set_catalog_meta($dbh, 'created_at', time);
    set_catalog_meta($dbh, 'dataset_name', $opts{dataset}) if defined $opts{dataset};
}

sub catalog_meta {
    my ($dbh, $key) = @_;
    my ($v) = $dbh->selectrow_array('SELECT value FROM meta WHERE key = ?', undef, $key);
    return $v;
}

sub set_catalog_meta {
    my ($dbh, $key, $value) = @_;
    $dbh->do('INSERT OR REPLACE INTO meta(key, value) VALUES(?, ?)', undef, $key, $value);
}

sub upsert_volume {
    my ($dbh, %v) = @_;
    $dbh->do(<<'SQL', undef, $v{hostname}, $v{volume}, $v{mount_point}, $v{os}, time);
INSERT INTO volumes(hostname, volume, mount_point, os, scanned_at)
VALUES(?, ?, ?, ?, ?)
ON CONFLICT(hostname, volume) DO UPDATE SET
  mount_point = excluded.mount_point,
  os          = excluded.os,
  scanned_at  = excluded.scanned_at
SQL
    return get_volume($dbh, $v{hostname}, $v{volume});
}

sub get_volume {
    my ($dbh, $hostname, $volume) = @_;
    return $dbh->selectrow_hashref(
        'SELECT * FROM volumes WHERE hostname = ? AND volume = ?',
        undef, $hostname, $volume,
    );
}

sub volumes {
    my $dbh = shift;
    return $dbh->selectall_arrayref(
        'SELECT * FROM volumes ORDER BY hostname, volume',
        { Slice => {} },
    );
}

my $JSON = JSON::PP->new->utf8->canonical;
sub json_decode { $JSON->decode($_[0]) }
sub json_encode { $JSON->encode($_[0]) }

sub jsonl_reader {
    my $path = shift;
    open my $fh, '<:raw', $path or die "$path: $!\n";
    return sub {
        my $line = <$fh>;
        return undef unless defined $line;
        chomp $line;
        return {} unless length $line;
        return json_decode($line);
    };
}

sub jsonl_writer {
    my $path = shift;
    open my $fh, '>:raw', $path or die "$path: $!\n";
    return (sub {
        my $obj = shift;
        print {$fh} json_encode($obj), "\n";
    }, sub { close $fh });
}

1;
