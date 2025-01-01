#include "czkatran/lib/BpfLoater.h"

#include <glog/logging.h>


namespace czkatran {
namespace {
    constexpr int KERROR = 1;
    constexpr int KSUCCESS = 0;
    constexpr int KNOEXISTS = -1;
    constexpr int KSHARED_MAP_NAME_LEN_MAX = 15; 
} // namespace

namespace {
std::string libbpf_error_msg(int err) {
    char buf[128];
    ::libbpf_strerror(err, buf, sizeof(buf));
    return std::string(buf);
}

void checkBpfProgType(::bpf_object *obj, ::bpf_prog_type type) {
    if(type == BPF_PROG_TYPE_UNSPEC) {
        return;
    }
    ::bpf_program *prog;
    bpf_object__for_each_program(prog, obj) {
        CHECK_EQ(bpf_program__type(prog), type);
    }
}

}


BpfLoader:: BpfLoader() {
    VLOG(1) << "BpfLoader constructor called, Enabled libbpf strcit mode";
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
}

BpfLoader:: ~BpfLoader() {
    for (auto& obj : bpf_Name_Objects_) {
        closeBpfObject(obj.second); //对象析构，关闭所有bpf_object
    }
    VLOG(1) << "BpfLoader destructor called"; //debug
}

int BpfLoader:: closeBpfObject(::bpf_object *obj) {
    if(obj == nullptr) {
        LOG(ERROR) << "Invalid bpf_object pointer"; //debug
        return KERROR;
    }
    ::bpf_object__close(obj);
    return KSUCCESS;
}

int BpfLoader:: getMapFdByName(const std::string& name) {
    auto it = maps_Name_Fd_.find(name);
    if(it == maps_Name_Fd_.end()) {
        LOG(ERROR) << "Map name not found: " << name;
        return KNOEXISTS;
    } else {
        return it->second;
    }
    return KERROR;
}

int BpfLoader:: getProgFdByName(const std::string& name) {
    auto it = progs_Name_Fd_.find(name);
    if(it == progs_Name_Fd_.end()) {
        LOG(ERROR) << "Prog name not found: " << name;
        return KNOEXISTS;
    } else {
        return it->second;
    }
    return KERROR;
}

bool BpfLoader:: isMapInProg(const std::string& MapName, 
                            const std::string& ProgName) {
    auto it = current_map_inner_maps_.find(ProgName);
    if(it == current_map_inner_maps_.end()) {
        LOG(ERROR) << "Prog name not found: " << ProgName;
        return KERROR;
    }
    return it->second.find(MapName) != it->second.end();
}

int BpfLoader:: setInnerMapProtoType(const std::string& name, 
                                    int fd) {
    auto it = inner_Map_prototypes_.find(name);
    if(it != inner_Map_prototypes_.end()) {
        LOG(ERROR) << "Inner map name already exists: " << name;
        return KERROR;
    }
    inner_Map_prototypes_[name] = fd;
    return KSUCCESS;
}

int BpfLoader:: updateSharedMap(const std::string& name, 
                                int fd) {
    auto it = shared_maps_Name_Fd_.find(name);
    if(it != shared_maps_Name_Fd_.end()) {
        LOG(ERROR) << "Shared map name already exists: " << name;
        return KNOEXISTS;
    } else if(name.size() > KSHARED_MAP_NAME_LEN_MAX) {
        LOG(ERROR) << "Shared map name too long: " << name;
        return KNOEXISTS;
    } else {
        shared_maps_Name_Fd_[name] = fd;
        return KSUCCESS;
    }
    return KERROR;
}

const char* BpfLoader:: getProgNameByFromBpfProg(const struct bpf_program *prog) {
    return ::bpf_program__name(prog);
}

int BpfLoader:: loadBpfFile(const std::string& path, 
                           const bpf_prog_type type, 
                           bool use_names) {
    auto obj = ::bpf_object__open_file(path.c_str(), NULL);
    const auto err = ::libbpf_get_error(obj);
    if(err) {
        LOG(ERROR) << "Failed to open BPF object file: " << path <<
            ", error: " << libbpf_error_msg(err);
        return KERROR;
    }

    return loadBpfObject(obj, path, type);
}

int BpfLoader:: reloadBpfFromFile(const std::string& path, 
                               const bpf_prog_type type) {
    auto obj = ::bpf_object__open_file(path.c_str(), NULL);
    const auto err = ::libbpf_get_error(obj);
    if(err) {
        LOG(ERROR) << "Failed to open BPF object file: " << path <<
            ", error: " << libbpf_error_msg(err);
        return KERROR;
    }

    return reloadBpfObject(obj, path, type);
}

int BpfLoader:: loadBpfFromBuffer(
            const char *buf,
            int buf_size,
            const bpf_prog_type type,
            bool use_names = false,
            const char * objname) {
    LIBBPF_OPTS(bpf_object_open_opts, opts, .object_name = objname);
    auto obj = ::bpf_object__open_mem(buf, buf_size, &opts);
    auto err = ::libbpf_get_error(obj);
    if(err) {
        LOG(ERROR) << "Failed to open BPF object from buffer, error: " << libbpf_error_msg(err);
    }
    return loadBpfObject(obj, objname, type);
}

//核心函数 --加载obj
int BpfLoader:: loadBpfObject(
        ::bpf_object *obj,
        const std::string& objName,
        const bpf_prog_type type
      ) {

    auto it = bpf_Name_Objects_.find(objName);
    if(it != bpf_Name_Objects_.end()) {
        LOG(ERROR) << "BPF object name already exists: " << objName;
        return closeBpfObject(obj);
    }

    ::bpf_program *program;
    ::bpf_map * map;
    std::set<std::string> loaderProgNames;
    std::set<std::string> loaderMapNames;
    
    bpf_object__for_each_program(program, obj) {
        bpf_program__set_log_level(program, 4);
        auto it = progs_Name_Fd_.find(bpf_program__name(program));
        if(it != progs_Name_Fd_.end()) {
            LOG(ERROR) << "BPF program name already exists: " << bpf_program__name(program);
            return closeBpfObject(obj);
        }
    }

    bpf_map__for_each(map, obj) {
        auto map_name = bpf_map__name(map);
        auto shared_it = shared_maps_Name_Fd_.find(map_name);
        if(shared_it != shared_maps_Name_Fd_.end()) {
            VLOG(2) << "Shared map found: " << shared_it->first;
            if(::bpf_map__reuse_fd(map, shared_it->second)) {
                LOG(ERROR) << "Failed to reuse shared map: " << shared_it->first 
                           << " fd: " << shared_it->second;
                return closeBpfObject(obj);
            }
            continue;
        }

        if(maps_Name_Fd_.find(map_name) != maps_Name_Fd_.end()) {
            if(knownDuplicateMaps_.find(std::string(map_name)) != knownDuplicateMaps_.end()) {
                VLOG(2) << "bpf ignoring map collsision of - " << map_name;
                continue;
            }
            LOG(ERROR) << "bpf map name already exists: " << map_name;
            return closeBpfObject(obj);
        }

        auto inner_it = inner_Map_prototypes_.find(map_name);
        if(inner_it != inner_Map_prototypes_.end()) {
            VLOG(2) << "Inner map found: " << inner_it->first 
                    << " fd: " << inner_it->second;
            if(::bpf_map__set_inner_map_fd(map, inner_it->second)) {
                LOG(ERROR) << "Failed to set inner map: " << inner_it->first 
                           << " fd: " << inner_it->second;
                return closeBpfObject(obj);
            }
        }
    }
    if(::bpf_object__load(obj)) {
        LOG(ERROR) << "Failed to load BPF object: " << objName;
        return closeBpfObject(obj);
    }

    checkBpfProgType(obj, type);

    bpf_object__for_each_program(program, obj) {
        auto prog_name = bpf_program__name(program);
        VLOG(4) << "adding bpf program to map, name: " << prog_name 
                << " fd: " << ::bpf_program__fd(program);
        progs_Name_Fd_[prog_name] = ::bpf_program__fd(program);
        loaderProgNames.insert(prog_name);
    }

    bpf_map__for_each(map, obj) {
        auto map_name = bpf_map__name(map);
        VLOG(4) << "adding bpf map to map, name: " << map_name 
                << " fd: " << ::bpf_map__fd(map);
        maps_Name_Fd_[map_name] = ::bpf_map__fd(map);
        loaderMapNames.insert(map_name);
    }

    for(auto &progName : loaderProgNames) {
        current_map_inner_maps_[progName] = loaderMapNames;
    }

    bpf_Name_Objects_[objName] = obj;
    return KSUCCESS;
}

int BpfLoader:: reloadBpfObject(
        ::bpf_object *obj,
        const std::string& objName,
        const bpf_prog_type type) {
    ::bpf_program * program;
    ::bpf_map *map;
    std::set<std::string> loaderProgNames;
    std::set<std::string> loaderMapNames;
    bpf_object__for_each_program(program, obj) {
        auto prog_name = ::bpf_program__name(program);
        if(progs_Name_Fd_.find(prog_name) == progs_Name_Fd_.end()) {
            LOG(ERROR) << "BPF program name not found: " << prog_name;
            return closeBpfObject(obj);
        }
    }

    bpf_map__for_each(map, obj) {
        auto map_name = ::bpf_map__name(map);
        auto shared_it = shared_maps_Name_Fd_.find(map_name);
        if(shared_it != shared_maps_Name_Fd_.end()) {
            VLOG(2) << "Shared map found: " << shared_it->first
                    << " fd: " << shared_it->second;
            if(::bpf_map__reuse_fd(map, shared_it->second)) {
                LOG(ERROR) << "Failed to reuse shared map: " << shared_it->first 
                           << " fd: " << shared_it->second;
                return closeBpfObject(obj);
            }
            continue;
        }

        auto map_iter = maps_Name_Fd_.find(map_name);
        if(map_iter != maps_Name_Fd_.end()) {
            VLOG(2) << "map found: " << map_name 
                    << " fd: " << map_iter->second;
            if(updateSharedMap(map_name, map_iter->second)) {
                LOG(ERROR) << "Failed to update shared map: " 
                           << map_name << " fd: " << map_iter->second;
                return closeBpfObject(obj);
            }
            if(::bpf_map__reuse_fd(map, map_iter->second)) {
                LOG(ERROR) << "Failed to reuse map: " << map_name 
                           << " fd: " << map_iter->second;
                return closeBpfObject(obj);
            }
            continue;
        }

        auto inner_it = inner_Map_prototypes_.find(map_name);
        if(inner_it != inner_Map_prototypes_.end()) {
            VLOG(2) << "Inner map found: " << inner_it->first 
                    << "fd" << inner_it->second;
            if(::bpf_map__set_inner_map_fd(map, inner_it->second)) {
                LOG(ERROR) << "Failed to set inner map: " << inner_it->first 
                           << " fd: " << inner_it->second;
                return closeBpfObject(obj);
            }
        }
    }

    if(::bpf_object__load(obj)) {
        LOG(ERROR) << "Failed to load BPF object: " << objName;
        return closeBpfObject(obj);
    }

    checkBpfProgType(obj, type);

    bpf_object__for_each_program(program, obj) {
        auto prog_name = ::bpf_program__name(program);
        VLOG(4) << "close old bpf program name:" << prog_name;
        auto old_fd = progs_Name_Fd_[prog_name];
        ::close(old_fd);

        VLOG(4) << "adding new bpf program to map, name: " << prog_name 
                << " fd: " << ::bpf_program__fd(program); 
        progs_Name_Fd_[prog_name] = ::bpf_program__fd(program);
        loaderProgNames.insert(prog_name);
    }

    bpf_map__for_each(map, obj) {
        auto map_name = bpf_map__name(map);
        auto map_iter = maps_Name_Fd_.find(map_name);
        if(map_iter == maps_Name_Fd_.end()) {
            VLOG(4) << "adding new bpf map to map, name: " << map_name 
                    << " fd: " << ::bpf_map__fd(map);
            maps_Name_Fd_[map_name] = ::bpf_map__fd(map);
            loaderMapNames.insert(map_name);
        }
        //loaderMapNames.insert(map_name);
    }

    for(auto &progName : loaderProgNames) {
        current_map_inner_maps_[progName] = loaderMapNames;
    }

    bpf_Name_Objects_[objName] = obj;
    return KSUCCESS;
}


} //czkatran

