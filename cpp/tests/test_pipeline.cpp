#include "forensicator/pipeline.hpp"

#include <atomic>
#include <cassert>
#include <iostream>
#include <thread>
#include <vector>

using forensicator::BoundedQueue;

int main() {
    {
        BoundedQueue<int> q(8);
        std::atomic<int> sum{0};
        std::vector<std::thread> producers, consumers;
        for (int i = 0; i < 4; ++i) {
            producers.emplace_back([&, i] {
                for (int j = 0; j < 100; ++j) q.push(i * 100 + j);
            });
        }
        std::atomic<int> received{0};
        for (int i = 0; i < 2; ++i) {
            consumers.emplace_back([&] {
                while (true) {
                    auto v = q.pop();
                    if (!v) break;
                    sum.fetch_add(*v);
                    received.fetch_add(1);
                }
            });
        }
        for (auto& t : producers) t.join();
        q.close();
        for (auto& t : consumers) t.join();
        // 4 producers x 100 items each = 400, values 0..399
        assert(received.load() == 400);
        int expected = 0;
        for (int i = 0; i < 400; ++i) expected += i;
        // value range is [0..399] across producers (i*100+j)
        // sum_i sum_j (i*100+j) for i in 0..3, j in 0..99 ->
        //   100 * sum(i)*100 + 4 * sum(j) = 100*6*100 + 4*4950 = 60000 + 19800 = 79800
        assert(sum.load() == 79800);
    }
    {
        // close while waiting
        BoundedQueue<int> q(2);
        std::thread t([&] {
            auto v = q.pop();
            assert(!v);
        });
        q.close();
        t.join();
    }
    std::cout << "test_pipeline ok\n";
    return 0;
}
