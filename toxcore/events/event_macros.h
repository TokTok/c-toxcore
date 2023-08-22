/*****************************************************
 *
 * :: get/set
 *
 *****************************************************/

#define EV_ACCESS_VALUE(EVENT_TYPE, EVENT_NAME, MEMBER_TYPE, MEMBER_NAME) \
non_null() \
static void tox_event_##EVENT_NAME##_set_##MEMBER_NAME(Tox_Event_##EVENT_TYPE *EVENT_NAME, \
        MEMBER_TYPE MEMBER_NAME) \
{ \
    assert(EVENT_NAME != nullptr); \
    EVENT_NAME->MEMBER_NAME = MEMBER_NAME; \
} \
MEMBER_TYPE tox_event_##EVENT_NAME##_get_##MEMBER_NAME(const Tox_Event_##EVENT_TYPE *EVENT_NAME) \
{ \
    assert(EVENT_NAME != nullptr); \
    return EVENT_NAME->MEMBER_NAME; \
}

#define EV_ACCESS_FIXED(EVENT_TYPE, EVENT_NAME, MEMBER_TYPE, MEMBER_NAME, MEMBER_SIZE) \
non_null() \
static bool tox_event_##EVENT_NAME##_set_##MEMBER_NAME(Tox_Event_##EVENT_TYPE *EVENT_NAME, const uint8_t *MEMBER_NAME) \
{ \
    assert(EVENT_NAME != nullptr); \
 \
    memcpy(EVENT_NAME->MEMBER_NAME, MEMBER_NAME, MEMBER_SIZE); \
    return true; \
} \
const uint8_t *tox_event_##EVENT_NAME##_get_##MEMBER_NAME(const Tox_Event_##EVENT_TYPE *EVENT_NAME) \
{ \
    assert(EVENT_NAME != nullptr); \
    return EVENT_NAME->MEMBER_NAME; \
}

#define EV_ACCESS_ARRAY(EVENT_TYPE, EVENT_NAME, MEMBER_TYPE, MEMBER_NAME) \
non_null() \
static bool tox_event_##EVENT_NAME##_set_##MEMBER_NAME(Tox_Event_##EVENT_TYPE *EVENT_NAME, \
        const MEMBER_TYPE *MEMBER_NAME, uint32_t MEMBER_NAME##_length, const Memory *mem) \
{ \
    assert(EVENT_NAME != nullptr); \
 \
    if (EVENT_NAME->MEMBER_NAME != nullptr) { \
        mem_delete(mem, EVENT_NAME->MEMBER_NAME); \
        EVENT_NAME->MEMBER_NAME = nullptr; \
        EVENT_NAME->MEMBER_NAME##_length = 0; \
    } \
 \
    EVENT_NAME->MEMBER_NAME = (MEMBER_TYPE *)mem_balloc(mem, MEMBER_NAME##_length * sizeof(MEMBER_TYPE)); \
 \
    if (EVENT_NAME->MEMBER_NAME == nullptr) { \
        return false; \
    } \
 \
    memcpy(EVENT_NAME->MEMBER_NAME, MEMBER_NAME, MEMBER_NAME##_length * sizeof(MEMBER_TYPE)); \
    EVENT_NAME->MEMBER_NAME##_length = MEMBER_NAME##_length; \
    return true; \
} \
uint32_t tox_event_##EVENT_NAME##_get_##MEMBER_NAME##_length(const Tox_Event_##EVENT_TYPE *EVENT_NAME) \
{ \
    assert(EVENT_NAME != nullptr); \
    return EVENT_NAME->MEMBER_NAME##_length; \
} \
const MEMBER_TYPE *tox_event_##EVENT_NAME##_get_##MEMBER_NAME(const Tox_Event_##EVENT_TYPE *EVENT_NAME) \
{ \
    assert(EVENT_NAME != nullptr); \
    return EVENT_NAME->MEMBER_NAME; \
}

/*****************************************************
 *
 * :: new/free/add/get/size/unpack
 *
 *****************************************************/

#define EV_FUNCS(EVENT_TYPE, EVENT_NAME, EVENT_ENUM) \
const Tox_Event_##EVENT_TYPE *tox_event_get_##EVENT_NAME( \
    const Tox_Event *event) \
{ \
    return event->type == TOX_EVENT_##EVENT_ENUM ? event->data.EVENT_NAME : nullptr; \
} \
 \
Tox_Event_##EVENT_TYPE *tox_event_##EVENT_NAME##_new(const Memory *mem) \
{ \
    Tox_Event_##EVENT_TYPE *const EVENT_NAME = \
        (Tox_Event_##EVENT_TYPE *)mem_alloc(mem, sizeof(Tox_Event_##EVENT_TYPE)); \
 \
    if (EVENT_NAME == nullptr) { \
        return nullptr; \
    } \
 \
    tox_event_##EVENT_NAME##_construct(EVENT_NAME); \
    return EVENT_NAME; \
} \
 \
void tox_event_##EVENT_NAME##_free(Tox_Event_##EVENT_TYPE *EVENT_NAME, const Memory *mem) \
{ \
    if (EVENT_NAME != nullptr) { \
        tox_event_##EVENT_NAME##_destruct(EVENT_NAME, mem); \
    } \
    mem_delete(mem, EVENT_NAME); \
} \
 \
non_null() \
static Tox_Event_##EVENT_TYPE *tox_events_add_##EVENT_NAME(Tox_Events *events, const Memory *mem) \
{ \
    Tox_Event_##EVENT_TYPE *const EVENT_NAME = tox_event_##EVENT_NAME##_new(mem); \
 \
    if (EVENT_NAME == nullptr) { \
        return nullptr; \
    } \
 \
    Tox_Event event; \
    event.type = TOX_EVENT_##EVENT_ENUM; \
    event.data.EVENT_NAME = EVENT_NAME; \
 \
    tox_events_add(events, &event); \
    return EVENT_NAME; \
} \
 \
const Tox_Event_##EVENT_TYPE *tox_events_get_##EVENT_NAME( \
    const Tox_Events *events, uint32_t index) \
{ \
    uint32_t EVENT_NAME##_index = 0; \
 \
    for (uint32_t i = 0; i < events->events_size; ++i) { \
        if (EVENT_NAME##_index > index) { \
            return nullptr; \
        } \
 \
        if (events->events[i].type == TOX_EVENT_##EVENT_ENUM) { \
            const Tox_Event_##EVENT_TYPE *EVENT_NAME = events->events[i].data.EVENT_NAME; \
            if (EVENT_NAME##_index == index) { \
                return EVENT_NAME; \
            } \
            ++EVENT_NAME##_index; \
        } \
    } \
 \
    return nullptr; \
} \
 \
uint32_t tox_events_get_##EVENT_NAME##_size( \
    const Tox_Events *events) \
{ \
    uint32_t EVENT_NAME##_size = 0; \
 \
    for (uint32_t i = 0; i < events->events_size; ++i) { \
        if (events->events[i].type == TOX_EVENT_##EVENT_ENUM) { \
            ++EVENT_NAME##_size; \
        } \
    } \
 \
    return EVENT_NAME##_size; \
} \
 \
bool tox_event_##EVENT_NAME##_unpack( \
    Tox_Event_##EVENT_TYPE **event, Bin_Unpack *bu, const Memory *mem) \
{ \
    assert(event != nullptr); \
    *event = tox_event_##EVENT_NAME##_new(mem); \
 \
    if (*event == nullptr) { \
        return false; \
    } \
 \
    return tox_event_##EVENT_NAME##_unpack_into(*event, bu); \
} \
 \
non_null() \
static Tox_Event_##EVENT_TYPE *tox_event_##EVENT_NAME##_alloc(void *user_data) \
{ \
    Tox_Events_State *state = tox_events_alloc(user_data); \
    assert(state != nullptr); \
 \
    if (state->events == nullptr) { \
        return nullptr; \
    } \
 \
    Tox_Event_##EVENT_TYPE *EVENT_NAME = tox_events_add_##EVENT_NAME(state->events, state->mem); \
 \
    if (EVENT_NAME == nullptr) { \
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC; \
        return nullptr; \
    } \
 \
    return EVENT_NAME; \
}

