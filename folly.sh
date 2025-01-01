#下载安装依赖 folly
cd
git clone https://github.com/facebook/folly.git 
cd folly
./build/fbcode_builder/getdeps.py install-system-deps --dry-run --recursive

sudo apt-get install -y libgoogle-glog-dev #glog
sudo apt-get install libgtest-dev #gtest
