#pragma once

#include <string>
#include <folly/Function.h>
#include <unordered_map>
#include <vector>

#include "BaseBpfAdapter.h"
#include "BpfLoater.h"


extern "C" {
    #include <bpf/bpf.h>
    #include <linux/perf_event.h>
}

namespace czkatran {

class BpfAdapter : public BaseBpfAdapter {
    public:
        explicit BpfAdapter(bool set_limit,
                           bool enableBatchOpsIfSupported);

        BpfAdapter(BpfAdapter &bpf_adapter) = delete;
        BpfAdapter& operator=(BpfAdapter &bpf_adapter) = delete;    

        int loadBpfProg(const std::string& bpf_prog,
                       const bpf_prog_type type = BPF_PROG_TYPE_UNSPEC,
                       bool use_names = false) override;

        int loadBpfProg(
            const char *buf,
            int buf_size,
            const ::bpf_prog_type type = BPF_PROG_TYPE_UNSPEC,
            bool use_names = false,
            const char * objname = "buffer") override;
        
        int reloadBpfProg(const std::string& bpf_prog,
                         const bpf_prog_type type = BPF_PROG_TYPE_UNSPEC) override;
        
        int getMapFdByName(const std::string& name) override;

        bool isMapInProg(const std::string& progName, const std::string& mapName) override; 

        int setInnerMapProtoType(const std::string& name, int fd) override;
        
        int getProgFdByName(const std::string& name) override;

        int updateSharedMap(const std::string& name, int fd) override;

    private:
        BpfLoader *bpf_loader_;

};
}





