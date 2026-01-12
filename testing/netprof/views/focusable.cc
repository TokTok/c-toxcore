#include "focusable.hh"

namespace tox::netprof::views {

FocusableComponent::FocusableComponent(ftxui::Component child) { Add(std::move(child)); }

FocusableComponent::~FocusableComponent() = default;

bool FocusableComponent::Focusable() const { return true; }

ftxui::Component make_focusable(ftxui::Component child)
{
    return std::make_shared<FocusableComponent>(std::move(child));
}

}  // namespace tox::netprof::views
