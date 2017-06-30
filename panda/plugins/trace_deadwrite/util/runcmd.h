


#include <iostream>
#include <stdexcept>
#include <stdio.h>
#include <string>

std::string runcmd(const char* cmd);


// cite: https://stackoverflow.com/questions/478898/how-to-execute-a-command-and-get-output-of-command-within-c-using-posix

// pre-c++11 version.

std::string runcmd(const char* cmd) {
    char buffer[128];
    std::string result = "";
    FILE* pipe = popen(cmd, "r");
    if (!pipe) throw std::runtime_error("popen() failed!");
    try {
        while (!feof(pipe)) {
            if (fgets(buffer, 128, pipe) != NULL)
                result += buffer;
        }
    } catch (...) {
        pclose(pipe);
        throw;
    }
    pclose(pipe);
    return result;
}


// int main(){
//     std::string result ;
//     result = runcmd("ls");
//     std::cout << result << std::endl;
// }


// c++11 version:
// #include <cstdio>
// #include <iostream>
// #include <memory>
// #include <stdexcept>
// #include <string>
// #include <array>

// std::string exec(const char* cmd) {
//     std::array<char, 128> buffer;
//     std::string result;
//     std::shared_ptr<FILE> pipe(popen(cmd, "r"), pclose);
//     if (!pipe) throw std::runtime_error("popen() failed!");
//     while (!feof(pipe.get())) {
//         if (fgets(buffer.data(), 128, pipe.get()) != NULL)
//             result += buffer.data();
//     }
//     return result;
// }

// //install libpstreams-dev
// #include <pstream.h> 
// #include <string>
// #include <iostream>

// int main()
// {
//   // run a process and create a streambuf that reads its stdout and stderr
//   std::string cmd = "addr2line " + "-e bin " + "0x99" ;

//   redi::ipstream proc("addr2line ", redi::pstreams::pstdout | redi::pstreams::pstderr);
//   std::string line;
//   // read child's stdout
//   while (std::getline(proc.out(), line))
//     std::cout << "stdout: " << line << '\n';
//   // read child's stderr
//   while (std::getline(proc.err(), line))
//     std::cout << "stderr: " << line << '\n';
// } 
