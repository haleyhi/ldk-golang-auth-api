package auth_client

import (
	"errors"
	"os"
	"time"

	filelock "github.com/zbiljic/go-filelock"
)

var ErrTimeout = errors.New("lock timeout")



type FileLock struct {
	flock filelock.TryLockerSafe
}

func NewFl(filename string) (*FileLock, error) {
	var err error
	dir, err := os.UserHomeDir()
	if err != nil {
		Log.Errorf("get dir error: %v", err)
		return nil, err
	}
	fl, err := filelock.New(dir + "/" + filename)
	if err != nil {
		Log.Errorf("new lock error, %v", err)
		return nil, err
	}
	f := &FileLock{
		flock: fl,
	}
	return f, nil
}

func (l *FileLock) LockWithTimeout(timeout time.Duration) error {

	timeoutChan := time.After(timeout * time.Second)
	lockChan := make(chan error, 1)
	go func() { lockChan <- l.flock.Lock() }()
	select {
	case <-timeoutChan:
		go func() {
			l.flock.Unlock()

		}()
		return ErrTimeout

	case lockErr := <-lockChan:
		if lockErr != nil {
			return lockErr
		}
	}
	return nil

}
func (l *FileLock) Unlock() error {
	return l.flock.Unlock()
}

func (l *FileLock) Destroy(filename string) error {
	l.flock.Destroy()
	dir, err := os.UserHomeDir()
	if err != nil {
		Log.Errorf("get dir error: %v", err)
		return err
	}
	os.Remove(dir + "/" + filename)
	return nil
}
