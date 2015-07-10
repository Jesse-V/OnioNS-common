
#ifndef FLAGS_HPP
#define FLAGS_HPP

#include <string>

class Flags
{
 public:
  static Flags& get()
  {
    static Flags instance;
    return instance;
  }

  bool parse(int argc, char** argv);
  std::string getKeyPath() const;

 private:
  Flags() {}
  Flags(Flags const&) = delete;
  void operator=(Flags const&) = delete;

  std::string keyPath_;
};

#endif
