package pro.javacard.applets;

/**
 * This class saves a log of the instruction sent to the passport as follows:
 * 
 * [session nr byte] [length of data byte] [data] ...
 * 
 * The data is a sequence of the instruction bytes, special cases:
 * 
 * SELECT_FILE: followed by the file identifier (2 bytes) 
 *
 * When the same instruction is called consequtively, only one is recorded,
 * but this byte is followed by FF <nr of consequtive calls>
 * 
 * FIXME: When the log exceeds log.length, the counter is wrapped, but this
 * breaks the format.
 * 
 * @author ceesb
 * 
 */
class PassportLog {
    private byte[] log;
    private short sessionBase;
    private short sessionOffset;
    private short sessions;
    private short insCount;
    private short prevIns;
    boolean enabled;

    PassportLog(PassportFileSystem filesystem) {
        filesystem.createFile(PassportFileSystem.SOS_LOG_FID, (short) 128);
        log = filesystem.getFile(PassportFileSystem.SOS_LOG_FID);
    }

    private void writeLogByte(byte b) {
        writeLogByteNoUpdate(b);
        sessionOffset++;
        sessionOffset %= log.length;        
    }
        
    private void writeLogByteNoUpdate(byte b) {
        log[(byte) ((sessionBase + sessionOffset) & 0xff)] = b;
        log[(byte) (sessionBase + 1)] = (byte) (sessionOffset & 0xff);
    }
    

    public void enabled(boolean v) {
        enabled = v;
    }

    public void newSession() {
        if (!enabled) {
            return;
        }
        sessionBase = sessionOffset;
        sessionOffset = 0;
        writeLogByteNoUpdate((byte) (sessions++ & 0xff));
        sessionOffset = 2;
    }

    public void insByte(byte ins) {
        if (!enabled) {
            return;
        }
        
        if(ins == prevIns) {
            writeLogByte((byte)0xff);
            writeLogByte((byte)(++insCount & 0xff));
            sessionOffset -= 2;
        }
        else if(insCount > 0) {
            sessionOffset += 2;
            insCount = 0;
            writeLogByte(ins);
        }
        else {
            writeLogByte(ins);            
        }
        
        prevIns = ins;
    
    }

    public void selectFile(short fid) {
        if (!enabled) {
            return;
        }
        writeLogByte((byte) ((fid >>> 8) & 0xff));
        writeLogByte((byte) (fid & 0xff));
    }
}
