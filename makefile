CXX = g++
CXXFLAGS = -Wall -Wextra
LIBS = -lpcap

TARGET = beaconflood
SRCS = beaconflood.cpp

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRCS) $(LIBS)
clean:
	rm -f $(OBJS) $(TARGET)
