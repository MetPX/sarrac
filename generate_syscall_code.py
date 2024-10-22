# Generates syscall passthrough code
# Each part is wrapped with #ifdef SYS_... and #endif, because not all architectures have all the same syscalls.
# For example, shmat and shmdt are not defined on PPC
import subprocess

# exclusions: syscalls to not generate code for
EXCLUDE = ['renameat2'] # and mremap? # clone, fanotify_mark and sigsuspend have multiple signatures.

# Because arguments are sometimes defined without variable names, we need to differentiate between unsigned types.
# For example, 'unsigned long,' is an argument of type 'unsigned long' with no variable name. It is NOT a variable
# of type 'unsigned' named 'long'.
# Also, types with the most number of words should be defined first. E.g. 'unsigned long long int' must come before
# 'unsigned long int' and 'unsigned long', etc.
UNSIGNED_TYPES = ['unsigned char', 'unsigned short', 'unsigned int', 'unsigned long long int', 'unsigned long int', 
                  'unsigned long', ]

# Certain argument types passed to variadic functions get "upconverted" to larger types. See
# https://stackoverflow.com/questions/23983471/char-is-promoted-to-int-when-passed-through-in-c
SPECIAL_TYPES = {"umode_t":"unsigned int"}

# print debug info for these syscalls
DEBUG = ['accept', 'chmod', 'capget', 'clone' ]

# keep track of all the types we've seen
all_types = set()

def which_unsigned_type(arg):
    ret = False
    for utype in UNSIGNED_TYPES:
        if utype in arg:
            ret = utype
            break
    return ret

def get_syscall_signatures():
    """ Return the function signatures of each syscall by parsing /usr/src/.../include/linux/syscalls.h
        awk command is from https://stackoverflow.com/a/92395
    """
    # File locations for RedHat and Debian are different. Try RedHat first, then Debian, then fail and return an empty dictionary.
    redhat_cmd = """awk '/^asmlinkage.*sys_/{gsub(/[[:space:]]+/, " "); printf $0; while ($0 !~ /;/) { getline; gsub(/[[:space:]]+/, " "); printf $0 } printf "\\n" }'  /usr/src/kernels/$(uname -r)/include/linux/syscalls.h"""
    debian_cmd = """awk '/^asmlinkage.*sys_/{gsub(/[[:space:]]+/, " "); printf $0; while ($0 !~ /;/) { getline; gsub(/[[:space:]]+/, " "); printf $0 } printf "\\n" }'  /usr/src/linux-headers-$(uname -r)/include/linux/syscalls.h"""
    
    result = subprocess.run(redhat_cmd, shell=True, stdout=subprocess.PIPE)
    if result.returncode != 0:
        # try Debian
        result = subprocess.run(debian_cmd, shell=True, stdout=subprocess.PIPE)
    
    if result.returncode != 0:
        print("Failed to get syscall signatures")
        return {}

    signatures = {}
    for line in result.stdout.split(b'\n'):
        line = line.decode('utf-8')
        if len(line) <= 0:
            continue
        # print(line)
        line = line.replace("asmlinkage long ", "")
        parts = line.split('(')
        name = parts[0].replace('sys_', '')
        args = [arg.strip() for arg in parts[1].split(')')[0].split(',')]
        if name not in signatures:
            signatures[name] = args
        else:
            print(f"WARNING: multiple signatures for {name}.\n\t new signature is {args}\n\t old signature is {signatures[name]}\n")

        if name in DEBUG:
            print(line, '\n', name, args)
            print()

    return signatures

def syscall_to_code(name, signature):
    cleanup = ["__user ", "const "]
    output = ""
    output += f"""\t#ifdef SYS_{name}\n"""
    output += f"""\t}} else if (__sysno == SYS_{name} && syscall_fn_ptr) {{\n"""
    output += f"""\t\tsr_shimdebug_msg(1, "syscall %ld --> {name}, will pass along\\n", __sysno);\n"""

    arg_names = []
    if 'void' not in signature:
        output += """\t\tva_start(syscall_args, __sysno);\n"""

        for arg in signature:
            for thing in cleanup:
                arg = arg.replace(thing, "")
            
            if '*' in arg:
                idx = arg.rfind('*')
            else:
                # need to handle cases of unsigned something with no arg name (e.g. clone)
                put_back_unsigned = False
                utype = None
                if 'unsigned' in arg:
                    utype = which_unsigned_type(arg)
                    if utype:
                        arg = arg.replace(utype, utype.replace(' ', '_'))
                        put_back_unsigned = True

                idx = arg.rfind(' ')

                if put_back_unsigned:
                    arg = arg.replace(utype.replace(' ', '_'), utype)
                    put_back_unsigned = False
            
            # handles the case where there's no variable name
            if idx != -1:
                data_type = arg[0:idx+1]
                var_name = arg[idx+1:]
            else:
                data_type = arg + ' '
                var_name = ''
            
            # not all signatures specify the variable names
            if len(var_name) == 0:
                var_name = f"unknown_name{len(arg_names)}"
            
            data_type = data_type.strip()
            if data_type in SPECIAL_TYPES:
                output += f"""\t\t{data_type} {var_name} = ({data_type})va_arg(syscall_args, {SPECIAL_TYPES[data_type]});\n"""
            else:
                output += f"""\t\t{data_type} {var_name} = va_arg(syscall_args, {data_type});\n"""
            all_types.add(data_type)
            arg_names.append(var_name)

            if name in DEBUG:
                print(f"SYSCALL={name} FULL ARG={arg}: data_type={data_type}, var_name={var_name}, idx={idx}")
        
        output += """\t\tva_end(syscall_args);\n"""
    
    output += """\t\tsyscall_status = syscall_fn_ptr(__sysno"""
    for arg_name in arg_names:
        output += f", {arg_name}"
    output += ");\n"
    output += f"""\t#endif\n"""

    return output

# main
syscalls = get_syscall_signatures()

with open('libsr3shim_syscalls.c', mode='w') as fd:
    for syscall in sorted(syscalls):
        if syscall in EXCLUDE:
            msg = f'// syscall {syscall} is excluded --> needs to be manually defined'
            print(msg)
            # fd.write(msg)
            continue
        code = syscall_to_code(syscall, syscalls[syscall])
        # print(code)
        fd.write(code)

print(all_types)
