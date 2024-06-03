package auth_client

import (
	"bytes"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/hidez8891/shm"
	ps "github.com/mitchellh/go-ps"
)

type ShareMem struct{
    GlobalName string
	W *shm.Memory 
	Flock *FileLock
	ClientId string
	FlDuation int
	ShDuation int
    cache     string
}

func NewShMem(clientId string, flDuation int, shDuation int)(*ShareMem, error){
	
    return &ShareMem{
		ClientId: clientId,
		FlDuation: flDuation,
		ShDuation: shDuation,
	}, nil
}

func (s *ShareMem)SetGlobalName()string{
	s.GlobalName = ""
	ppid := syscall.Getppid()
	p, err := ps.FindProcess(ppid)
	if err != nil {
		Log.Errorf("Invalid parent process, error : %s ", err)
		return ""
	} 
	if strings.Contains(p.Executable(), "hasp_rt") {
		ppid = p.PPid()
		Log.Info("Get partent of hasp_rt")
	}  	
	//code review: test electron application
	//new function for share memory, global name, filelock, lock in read and write.
	//reduce timeout to twice.
	//global name: "clientid+parent process id" is for both filelock and share memory
	s.GlobalName = s.ClientId + "-" + strconv.Itoa(ppid)
	//s.GlobalName = s.ClientId
	Log.Infof("global name : %s", s.GlobalName)
	return s.GlobalName
}

func (s *ShareMem)InitShMem() error{
    var err error
	//s.LockFlag = false
	s.Flock, err = NewFl(s.SetGlobalName())
	if err != nil {
		Log.Errorf("new lock error, %v", err)
	} 
	if s.Flock != nil {
		err = s.Flock.LockWithTimeout(time.Duration(s.FlDuation))
		if err != nil{
			Log.Errorf("lock timeout error, %v", err)
		}
	}
	s.W, err = shm.Open(s.GlobalName, 4096)
				if err != nil {
					s.W, err = shm.Create(s.GlobalName, 4096)
				}
	return err
}

func (s *ShareMem)ReadShMem() string {
	if s.W == nil{
		return ""
	}
	str := make([]byte, 4096)
	s.W.ReadAt(str, 0)
	if str[0] != 0{
		str = bytes.Trim(str, "\x00")
		aeskey := GetAES256Key(s.GlobalName)
		if aeskey != nil {
			return Decrypt(string(str), string(aeskey))
		}
	}	
	if s.Flock != nil {
		s.Flock.Unlock()
	}
	return ""
}

func (s *ShareMem)WriteShMem(str string)  {
	if s.W == nil{
	    return
	}
	aeskey := GetAES256Key(s.GlobalName)
	if aeskey != nil {
		s.cache = Encrypt(str, string(aeskey))
		s.W.WriteAt([]byte(s.cache), 0)
	} 
	if s.Flock != nil {
		s.Flock.Unlock()
	}
	return 
}

func (s *ShareMem)ClearShMem()  {
	if s.W == nil{
	    return
	}
	str := make([]byte, 4096)

	s.W.WriteAt(str, 0)
	
	return 
}

func (s *ShareMem) Close() {
	if s.Flock != nil {
		s.Flock.Unlock()
		s.Flock.Destroy(s.GlobalName)
	}
	s.W.Close()
}

func (s *ShareMem) CloseShMemWithTimeout() {

	time.Sleep(time.Duration(s.ShDuation) * time.Second)
	if s.cache != "" && s.Flock != nil{
		err := s.Flock.LockWithTimeout(time.Duration(s.FlDuation))
		if err != nil{
			Log.Errorf("lock timeout error, %v", err)
		}
		str := make([]byte, 4096)
		s.W.ReadAt(str, 0)
		if str[0] != 0{
			str = bytes.Trim(str, "\x00")
		}	
		s.Flock.Unlock()
		if string(str) == s.cache{
			s.Flock.Destroy(s.GlobalName)
		}
	}
	s.W.Close()

	return
}
