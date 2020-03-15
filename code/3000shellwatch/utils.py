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

def syscall_name(num):
    return _syscall_name(num).decode('utf-8')

def syscall_ret(code):
    try:
        return str(code) if code > 0 else '-' + errorcode[-code]
    except KeyError:
        return str(code)
