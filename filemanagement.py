import pickle


def load_pickle_default(location, default):
    try:
        with open(location, 'rb') as handle:
            return pickle.load(handle)
    except:
        return default


def load_ssids():
    return load_pickle_default('ssids.pickle', set())


def load_macs():
    return load_pickle_default('macs.pickle', set())


def load_vendors():
    return load_pickle_default('vendors.pickle', set())


def load_macs_to_track():
    return load_pickle_default('macs_to_track.pickle', set())


def load_macs_last_seen():
    return load_pickle_default('macs_last_seen.pickle', dict())


def update_ssids(new):
    with open('ssids.pickle', 'wb') as handle:
        pickle.dump(new, handle)


def update_macs(new):
    with open('macs.pickle', 'wb') as handle:
        pickle.dump(new, handle)


def update_vendors(new):
    with open('vendors.pickle', 'wb') as handle:
        pickle.dump(new, handle)


def update_macs_to_track(new):
    with open('macs_to_track.pickle', 'wb') as handle:
        pickle.dump(new, handle)


def update_macs_last_seen(new):
    with open('macs_last_seen.pickle', 'wb') as handle:
        pickle.dump(new, handle)
