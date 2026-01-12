#ifndef C_TOXCORE_TESTING_NETPROF_VIEWS_DHT_FILTER_HH
#define C_TOXCORE_TESTING_NETPROF_VIEWS_DHT_FILTER_HH

#include <ftxui/component/component.hpp>

#include "../model.hh"

namespace tox::netprof::views {

/**
 * @brief Creates the DHT Filter controls component.
 */
ftxui::Component dht_filter(UIModel &model);

}  // namespace tox::netprof::views

#endif  // C_TOXCORE_TESTING_NETPROF_VIEWS_DHT_FILTER_HH
