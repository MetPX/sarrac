# Generates syscall passthrough code from signatures found in /usr/src/kernels/...SRC_DIR.../include/linux/syscalls.h
# 
# Each part is wrapped with #ifdef SYS_... and #endif, because not all architectures have all the same syscalls.
# For example, shmat and shmdt are not defined on PPC.
#
# The generated code needs to be manually copied into libsr3shim.c.
#
# Tested on RHEL 8, 9 and Ubuntu 18.04, 20.04, 22.04.
# 

import subprocess

# exclusions: syscalls to not generate code for
EXCLUDE = ['close', 'dup2', 'dup3', 'link', 'linkat', 'rename', 'renameat', 'renameat2', 'rmdir', 
           'truncate', 'truncate64', 'unlink', 'unlinkat']

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
# DEBUG = ['accept', 'chmod', 'capget', 'clone' ]
DEBUG = []

# src directory, different on RedHat and Debian
SRC_DIR = { 'rhel':"/usr/src/kernels/$(uname -r)",
            'ubuntu':"/usr/src/linux-headers-$(uname -r)"
}

# compare syscalls from above with /usr/include/bits/syscall.h 
SYSDEF_FILE = "/usr/include/bits/syscall.h"

# when available, this table is all of the *implemented* syscalls
SYSCALL_TBL = { 'rhel':"/usr/src/kernels/$(uname -r)/arch/x86/entry/syscalls/syscall_64.tbl",
                'ubuntu':"https://git.launchpad.net/~ubuntu-kernel/ubuntu/+source/linux/+git/CODENAME/plain/arch/x86/entry/syscalls/syscall_64.tbl"
}

# keep track of all the types we've seen
all_types = set()

def read_unimplemented():
    """ Reads /usr/share/man/man2/unimplemented.2.gz and returns a set of unimplemented
        syscall names.
    """
    result = subprocess.run(f"zcat /usr/share/man/man2/unimplemented.2.gz", 
                            shell=True, stdout=subprocess.PIPE)
    if result.returncode != 0:
        print("ERROR: problem reading /usr/share/man/man2/unimplemented.2.gz")
        return set()

    txt = result.stdout.decode('utf-8')
    txt = txt[txt.find("NAME")+4 : txt.find(" \- unimplemented system calls")].replace('\n', '').replace(' ', '')
    return set(txt.split(','))

def read_syscall_defs():
    """ Returns a set of all syscalls defined in SYSDEF_FILE.
    """
    syscalls = set()
    with open(SYSDEF_FILE) as fd:
        for line in fd.readlines():
            if 'define' in line and 'SYS_' in line:
                parts = line.split()
                syscall = parts[2].strip().replace('SYS_', '')
                syscalls.add(syscall)
    return syscalls

def read_syscall_tbl(os_name='rhel'):
    """ Returns a set of all syscalls defined in syscall_64.tbl
        os_name should either be 'rhel' or 'ubuntu'
    """
    syscalls = set()
    if os_name == 'rhel':
        table = SYSCALL_TBL['rhel'].replace("$(uname -r)", get_uname_r())
    elif os_name == 'ubuntu':
        table = SYSCALL_TBL['ubuntu'].replace("CODENAME", get_ubuntu_codename())
    else:
        print(f"ERROR: read_syscall_tbl failed, unknown OS {os_name}")
        return syscalls
    
    try:
        if os_name == 'rhel':
            fd = open(table)
            tbl = fd.readlines()
            fd.close()
        elif os_name == 'ubuntu':
            import requests
            resp = requests.get(table)
            resp.raise_for_status()
            tbl = resp.text.split('\n')
        
        # parse
        for line in tbl:
            if '#' not in line and len(line) > 1:
                parts = line.split()
                syscalls.add(parts[2].strip())
        
    except Exception as e:
        print(f"ERROR: problem reading {table}: {e}")
    return syscalls

def get_os_id():
    """ Tries to return the OS name. Should return 'rhel', 'ubuntu', or None if it fails.
    """
    try:
        with open('/etc/os-release') as fd:
            for line in fd.readlines():
                if line.startswith("ID="):
                    name=line.split("ID=")[-1].replace('"','').lower().strip()
                    return name
    except:
        return None

def get_uname_r():
    result = subprocess.run("uname -r", shell=True, stdout=subprocess.PIPE)
    if result.returncode != 0:
        print("ERROR: uname -r failed")
        return ""
    return result.stdout.split(b'\n')[0].decode('utf-8')

def get_ubuntu_codename():
    result = subprocess.run("lsb_release -cs", shell=True, stdout=subprocess.PIPE)
    if result.returncode != 0:
        print("ERROR: lsb_release -cs failed")
        return ""
    return result.stdout.split(b'\n')[0].decode('utf-8')

def which_unsigned_type(arg):
    ret = False
    for utype in UNSIGNED_TYPES:
        if utype in arg:
            ret = utype
            break
    return ret

def get_syscall_signatures(os_name='rhel'):
    """ Return the function signatures of each syscall by parsing /usr/src/.../include/linux/syscalls.h
        awk command is from https://stackoverflow.com/a/92395
    """
    cmd = """awk '/^asmlinkage.*sys_/{gsub(/[[:space:]]+/, " "); printf $0; while ($0 !~ /;/) { getline; gsub(/[[:space:]]+/, " "); printf $0 } printf "\\n" }'  """

    # File locations for RedHat and Debian are different. Try RedHat first, then Debian, then fail and return an empty dictionary.
    result = subprocess.run(cmd+f"{SRC_DIR[os_name]}/include/linux/syscalls.h", shell=True, stdout=subprocess.PIPE)

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
osname = get_os_id()
print(f"Script running on {osname}\n")

syscalls = get_syscall_signatures(os_name=osname)

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

print('\n')

# Verification

# Check for missing syscalls. There are some syscalls that don't have signatures
# defined in /usr/src/.../include/linux/syscalls.h
syscalls_from_sigs = set(syscalls.keys())
syscalls_from_defs = read_syscall_defs()
syscalls_from_tbl  = read_syscall_tbl(os_name=osname)
unimplemented_syscalls = read_unimplemented()

# syscalls_in_defs_not_in_sigs = sorted(syscalls_from_defs - syscalls_from_sigs)
# print(f"{len(syscalls_in_defs_not_in_sigs)} syscalls defined in {SYSDEF_FILE} that are missing from syscall signatures:")
# print(syscalls_in_defs_not_in_sigs)

# sycalls_in_sigs_not_in_defs = sorted(syscalls_from_sigs - syscalls_from_defs)
# print(f"{len(sycalls_in_sigs_not_in_defs)} syscalls with signatures that are not defined in {SYSDEF_FILE}:")
# print(sycalls_in_sigs_not_in_defs)

syscalls_in_tbl_not_in_sigs = sorted(syscalls_from_tbl - syscalls_from_sigs)
# print(f"{len(syscalls_in_tbl_not_in_sigs)} syscalls defined in {REDHAT_SYSCALL_TBL} that are missing from syscall signatures:")
# print(syscalls_in_tbl_not_in_sigs)

implemented_syscalls_in_tbl_not_in_sigs = sorted(set(syscalls_in_tbl_not_in_sigs) - unimplemented_syscalls)
print("WARNING: These syscalls may need to be implemented manually:\n")
print(f"{len(implemented_syscalls_in_tbl_not_in_sigs)} IMPLEMENTED syscalls defined in {SYSCALL_TBL[osname]} with unknown function signatures:")
print(implemented_syscalls_in_tbl_not_in_sigs)

print()
print('# of known signatures =', len(syscalls_from_sigs))
print('# syscalls in table   =', len(syscalls_from_tbl))
