#pragma once

#include <set>
#include <string>
#include <unordered_map>

extern "C" {
    #include <bpf/libbpf.h>
}

namespace czkatran {
    /**
     * 这个类包装了bpf程序的加载和卸载，以及相关的BPF map操作
     */
    class BpfLoader {
     public:
        explicit BpfLoader(); //
        ~BpfLoader(); //

        /**
         * @brief 从buffer中加载BPF程序
         * @param char* buf ---指向elf object文件的buffer的指针
         * @param int buf_size ---buffer的大小
         * @param bpf_prog_type type ---程序类型，默认为BPF_PROG_TYPE_UNSPEC
         * @param bool use_names ---是否使用BPF map的名称作为key，默认为false
         * @param char* objname ---程序名称，默认为"buffer"
         * @return 0表示成功，其他表示失败
         */ 
        int loadBpfFromBuffer(
            const char *buf,
            int buf_size,
            const ::bpf_prog_type type = BPF_PROG_TYPE_UNSPEC,
            bool use_names = false,
            const char * objname = "buffer"); //


        /**
         * @brief 从文件中加载BPF程序
         * @param string& path ---elf object文件的路径
         * @param bpf_prog_type type ---程序的类型，默认为BPF_PROG_TYPE_UNSPEC
         * @param bool use_names ---是否使用BPF map的名称作为key，默认为false
         * @return 0表示成功，其他表示失败
         */
        int loadBpfFile(
            const std::string& path,
            const ::bpf_prog_type type = BPF_PROG_TYPE_UNSPEC,
            bool use_names = false); //

        /**
         * @brief 从文件中加载BPF程序
         * @param string& path ---elf object文件的路径
         * @param bpf_prog_type type ---程序的类型，默认为BPF_PROG_TYPE_UNSPEC
         * @return 0表示成功，其他表示失败
         */
        int reloadBpfFromFile(
            const std::string& path,
            const ::bpf_prog_type type = BPF_PROG_TYPE_UNSPEC); //
        
        
        /**
         * @brief 通过名字的得到fd
         * @param string& name ---BPF map的名称
         * @return 对应的BPF map的fd，如果没有找到，则返回-1
         */
        int getMapFdByName(const std::string& name); //

        /**
         * @brief 检查某个BPF program是否使用了某个BPF map
         * @param string& MapName ---BPF map的名称
         * @param string& ProgName ---BPF program的名称
         * @return 对应的BPF map的fd，如果没有找到，则返回-1
         */
        bool isMapInProg(const std::string& MapName, const std::string& ProgName); //


        /**
         * @brief 设置fd对应map（fd->name）
         * @param string& name ---BPF map的名称
         * @param int fd ---BPF map的fd
         * @return 0表示成功，其他表示失败
         */
        int setInnerMapProtoType(const std::string& name, int fd); //
        

        /**
         * @brief 通过名字的得到Progfd
         * @param string& name ---BPF program的名称
         * @return 对应的BPF program的fd，如果没有找到，则返回-1
         */
        int getProgFdByName(const std::string& name); //

        /**
         * @brief 更新共享map
         * @param string& name ---BPF program的名称
         * @param int fd ---BPF program的fd
         * @return 0表示成功，其他表示失败
         */
        int updateSharedMap(const std::string& name, int fd); //

     private:

      /**
       * @brief 加载BPF object
       *@param bpf_object* obj ---指向BPF object的指针
       *@param string& objName ---BPF object的名称
       *@param bpf_prog_type type ---BPF program的类型
       *@return 0表示成功，其他表示失败
       */
      int loadBpfObject(
        ::bpf_object *obj,
        const std::string& objName,
        const ::bpf_prog_type type = BPF_PROG_TYPE_UNSPEC
      );

      
       /**
       * @brief 重新加载bpf object
       *@param bpf_object* obj ---指向BPF object的指针
       *@param string& objName ---BPF object的名称
       *@param bpf_prog_type type ---BPF program的类型
       *@return 0表示成功，其他表示失败
       */
      int reloadBpfObject(
        ::bpf_object *obj,
        const std::string& objName,
        const ::bpf_prog_type type = BPF_PROG_TYPE_UNSPEC
      );
      
      /**
       * @brief 关闭BPF object
       * @param bpf_object* obj ---指向BPF object的指针
       * @return 0表示成功，其他表示失败
       */
      int closeBpfObject(
        ::bpf_object *obj
      ); //

      const char* getProgNameByFromBpfProg(
        const struct bpf_program *prog
      ); //
      
      //map: path --> bpf_object
      std::unordered_map<std::string, ::bpf_object*> bpf_Name_Objects_;

      //map: name(bpf_map) --> fd(bpf_map)
      std::unordered_map<std::string, int> maps_Name_Fd_;

      //map: name(bpf_prog) --> fd(bpf_prog)
      std::unordered_map<std::string, int> progs_Name_Fd_;

      //map: name(shared_map) --> fd(shared_map)
      std::unordered_map<std::string, int> shared_maps_Name_Fd_;

      //map: name(inner_map) --> fd(inner_map)
      std::unordered_map<std::string, int> inner_Map_prototypes_;

      //map: current map name --> inner maps name
      std::unordered_map<std::string, std::set<std::string>> current_map_inner_maps_;

      const std::set<std::string> knownDuplicateMaps_ = {".rodata.str1.1"};

    };
}