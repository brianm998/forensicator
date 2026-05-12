// Pipeline orchestration utilities live entirely in the header
// (BoundedQueue is a template). This translation unit exists so the
// CMake target picks up the source set cleanly and gives us a place
// to add non-template helpers later without ABI churn.

#include "forensicator/pipeline.hpp"

namespace forensicator {
// nothing to define here yet
}  // namespace forensicator
