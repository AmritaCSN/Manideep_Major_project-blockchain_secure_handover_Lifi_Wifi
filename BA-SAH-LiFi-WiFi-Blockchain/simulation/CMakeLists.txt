#build_exec(
#  EXECNAME hybrid_full_v4
#  EXECNAME_PREFIX scratch_hybrid-project_
#  SOURCE_FILES
#    hybrid_full_v4.cc
#    fabric-ledger.cc
#    fabric-chaincode.cc
#  LIBRARIES_TO_LINK
#    ${libcore}
#    ${libnetwork}
#    ${libinternet}
#    ${libpoint-to-point}
#    ${libwifi}
#    ${libmobility}
#    ${libapplications}
#    ${libflow-monitor}
#    ${libnetanim}
#  EXECUTABLE_DIRECTORY_PATH
#    ${CMAKE_OUTPUT_DIRECTORY}/scratch/hybrid-project/
#)


build_exec(
  EXECNAME hybrid_full_v5
  EXECNAME_PREFIX scratch_hybrid-project_
  SOURCE_FILES
    hybrid_full_v5.cc
    fabric-ledger.cc
    fabric-chaincode.cc
  LIBRARIES_TO_LINK
    ${libcore}
    ${libnetwork}
    ${libinternet}
    ${libpoint-to-point}
    ${libwifi}
    ${libmobility}
    ${libapplications}
    ${libflow-monitor}
    ${libnetanim}
  EXECUTABLE_DIRECTORY_PATH
    ${CMAKE_OUTPUT_DIRECTORY}/scratch/hybrid-project/
)


#build_exec(
#  EXECNAME hybrid_full_v5_exp
#  EXECNAME_PREFIX scratch_hybrid-project_
#  SOURCE_FILES
#    hybrid_full_v5_exp.cc
#    fabric-ledger.cc
#    fabric-chaincode.cc
#  LIBRARIES_TO_LINK
#    ${libcore}
#    ${libnetwork}
#    ${libinternet}
#    ${libpoint-to-point}
#    ${libwifi}
#    ${libmobility}
#    ${libapplications}
#    ${libflow-monitor}
#    ${libnetanim}
#  EXECUTABLE_DIRECTORY_PATH
#    ${CMAKE_OUTPUT_DIRECTORY}/scratch/hybrid-project/
#)
