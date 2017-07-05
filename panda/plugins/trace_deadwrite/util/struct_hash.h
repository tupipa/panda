
#ifndef __UTIL_STRUCT_HASH_H_
#define __UTIL_STRUCT_HASH_H_


#include <cstdio>
#include <cstdlib>

#include <string>
#include <stdlib.h>

#include <tr1/unordered_map>


struct ProcID{
    OsiProc 

	bool operator==(const ProcID  & x) const{
		if ( this->procName == x.procName && this->asid == x.asid)
            return true;
		return false;
	}

	bool operator<(const ProcID  & x) const{
		if (this->asid < x.asid)
            return true;
		return false;
	}
};


namespace std {

  template <>
  struct hash<ProcID>
  {
    std::size_t operator()(const ProcID& k) const
    {
      using std::size_t;
      using std::hash;
      using std::string;

      // Compute individual hash values for first,
      // second and third and combine them using XOR
      // and bit shifting:

      return (hash<string>()(k.procName)
               ^ (hash<target_ulong>()(k.asid) << 1));
    }
  };

}

#endif