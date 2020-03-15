from errno import errorcode
from bcc.syscall import syscall_name  as _syscall_name

# Patch errorcode to add kernel-only errors
errorcode[512] = 'ERESTARTSYS'
errorcode[513] = 'ERESTARTNOINTR'
errorcode[514] = 'ERESTARTNOHAND'
errorcode[515] = 'ENOIOCTLCMD'
errorcode[516] = 'ERESTART_RESTARTBLOCK'
errorcode[517] = 'EPROBE_DEFER'
errorcode[518] = 'EOPENSTALE'
errorcode[521] = 'EBADHANDLE'
errorcode[522] = 'ENOTSYNC'
errorcode[523] = 'EBADCOOKIE'
errorcode[524] = 'ENOTSUPP'
errorcode[525] = 'ETOOSMALL'
errorcode[526] = 'ESERVERFAULT'
errorcode[527] = 'EBADTYPE'
errorcode[528] = 'EJUKEBOX'
errorcode[529] = 'EIOCBQUEUED'

signals = {
            1: 'SIGHUP',
            2: 'SIGINT',
            3: 'SIGQUIT',
            4: 'SIGILL',
            5: 'SIGTRAP',
            6: 'SIGABRT',
            7: 'SIGBUS',
            8: 'SIGFPE',
            9: 'SIGKILL',
            10: 'SIGUSR1',
            11: 'SIGSEGV',
            12: 'SIGUSR2',
            13: 'SIGPIPE',
            14: 'SIGALRM',
            15: 'SIGTERM',
            16: 'SIGSTKFLT',
            17: 'SIGCHLD',
            18: 'SIGCONT',
            19: 'SIGSTOP',
            20: 'SIGTSTP',
            21: 'SIGTTIN',
            22: 'SIGTTOU',
            23: 'SIGURG',
            24: 'SIGXCPU',
            25: 'SIGXFSZ',
            26: 'SIGVTALRM',
            27: 'SIGPROF',
            28: 'SIGWINCH',
            29: 'SIGIO',
            30: 'SIGPWR',
            31: 'SIGSYS',
        }

def syscall_name(num):
    return _syscall_name(num).decode('utf-8')

def syscall_ret(code):
    try:
        return str(code) if code > 0 else '-' + errorcode[-code]
    except KeyError:
        return str(code)

def signal_name(sig):
    try:
        return signals[sig]
    except KeyError:
        return f'UNKNOWN SIGNAL'
