#ifndef C_TOXCORE_TESTING_NETPROF_VIEWS_FOCUSABLE_HH
#define C_TOXCORE_TESTING_NETPROF_VIEWS_FOCUSABLE_HH

#include <ftxui/component/component_base.hpp>

namespace tox::netprof::views {

/**
 * @brief A component wrapper that makes its content focusable.
 */
class FocusableComponent : public ftxui::ComponentBase {
public:
    explicit FocusableComponent(ftxui::Component child);
    ~FocusableComponent() override;

    bool Focusable() const override;
};

ftxui::Component make_focusable(ftxui::Component child);

}  // namespace tox::netprof::views

#endif  // C_TOXCORE_TESTING_NETPROF_VIEWS_FOCUSABLE_HH
