# Detect git commit hash and working-tree dirtiness for build-time stamping.
# When git is unavailable or the tree is not a git checkout, both outputs are
# left empty / zero and no OBN_GIT_* compile definitions are added.

function(obn_detect_git_info out_commit out_dirty)
    set(_commit "")
    set(_dirty 0)

    find_program(_obn_git_executable git)
    if(_obn_git_executable)
        execute_process(
            COMMAND "${_obn_git_executable}" rev-parse --short=8 HEAD
            WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
            OUTPUT_VARIABLE _commit
            OUTPUT_STRIP_TRAILING_WHITESPACE
            ERROR_QUIET
            RESULT_VARIABLE _rev_rc
        )
        if(NOT _rev_rc EQUAL 0)
            set(_commit "")
        else()
            execute_process(
                COMMAND "${_obn_git_executable}" diff-index --quiet HEAD --
                WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
                RESULT_VARIABLE _dirty_rc
                ERROR_QUIET
            )
            if(NOT _dirty_rc EQUAL 0)
                set(_dirty 1)
            endif()
        endif()
    endif()

    set(${out_commit} "${_commit}" PARENT_SCOPE)
    set(${out_dirty} "${_dirty}" PARENT_SCOPE)
endfunction()
