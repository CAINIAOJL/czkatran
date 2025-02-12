#include "BpfAdapter.h"
#include <iostream>

namespace czkatran {

BpfAdapter:: BpfAdapter(bool set_limit,
                       bool enableBatchOpsIfSupported): 
                       BaseBpfAdapter(set_limit, enableBatchOpsIfSupported), 
                       bpf_loader_() //初始化bpf_loader_ 加载类
{}

int BpfAdapter:: loadBpfProg(const std::string& bpf_prog,
                       const bpf_prog_type type,
                       bool use_names) {
    // gdb debug
    std::cout << "in BpfAdapter loadBpfProg" <<std::endl;
    return bpf_loader_.loadBpfFile(bpf_prog, type, use_names);
    // gdb bubug
}

int BpfAdapter:: loadBpfProg(
            const char *buf,
            int buf_size,
            const ::bpf_prog_type type,
            bool use_names,
            const char * objname) {
    return bpf_loader_.loadBpfFromBuffer(buf, buf_size, type, use_names, objname);
}

int BpfAdapter:: reloadBpfProg(const std::string& bpf_prog,
                         const bpf_prog_type type) {
    return bpf_loader_.reloadBpfFromFile(bpf_prog, type);
}

int BpfAdapter:: getMapFdByName(const std::string& name) {
    return bpf_loader_.getMapFdByName(name);
}

bool BpfAdapter:: isMapInProg(const std::string& progName, const std::string& mapName) {
    return bpf_loader_.isMapInProg(progName, mapName);
}

int BpfAdapter:: setInnerMapProtoType(const std::string& name, int fd) {
    //return bpf_loader_->setInnerMapProtoType(name, fd);setInnerMapPrototype
    return bpf_loader_.setInnerMapPrototype(name, fd);
}

int BpfAdapter:: getProgFdByName(const std::string& name) {
    return bpf_loader_.getProgFdByName(name);
}

int BpfAdapter:: updateSharedMap(const std::string& name, int fd) {
    return bpf_loader_.updateSharedMap(name, fd);
}

}
