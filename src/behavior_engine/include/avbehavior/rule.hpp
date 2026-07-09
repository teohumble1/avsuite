#pragma once

#include <optional>
#include <string>

#include "avbehavior/process_event.hpp"
#include "avbehavior/process_tree.hpp"
#include "avcore/detection_event.hpp"

namespace avbehavior {

// One behavioral heuristic. Implementations must be cheap and non-blocking --
// Evaluate() is called for every process-creation event on the live ETW path.
class IRule {
public:
    virtual ~IRule() = default;
    virtual std::string Id() const = 0;
    virtual std::optional<avcore::DetectionEvent> Evaluate(const ProcessEvent& event,
                                                             const ProcessTree& tree) const = 0;
};

} // namespace avbehavior
