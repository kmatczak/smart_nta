add_executable(smart_nta smart_nta.c pkt_capture_ops.c )
target_link_libraries(smart_nta PRIVATE pcap)

# Add include directory
target_include_directories(smart_nta PUBLIC ${CMAKE_SOURCE_DIR}/include)

install(TARGETS smart_nta DESTINATION bin)
