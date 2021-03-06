package filesystem

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// TASKS
///////////////////////////////////////////////////////////////////////////////

// * File locking for reading and writing for atomicity
// Reference:
//
//   https://github.com/golang/go/blob/master/src/cmd/go/internal/lockedfile/mutex.go
//

// * Add ability to have error checking raptor/reed-solomon etc read/writes

// * zero-copy or something

// * Missing links, symlinks etc

// * Make a type that is a smart truncate for logs. It will chop off the first
// portion, leaving the remainder and then append to that amount. at a set
// amount of like 1 MB of data.

////////////////////////////////////////////////////////////////////////////////
// NOTE
// The goal is to be a very simple filesystem interface, simplifying interaction
// with the filesystem by abstracting a thin as possible layer making code
// expressive as possible. To be successful this file must stay small and not
// complex at all; but also should make working with filesystems very natural,
// and even have validation for security.
//
//   * **So far this model benefits greatly from avoiding holding locks or mem**
//   longer than absolutely necessary.
//
//   * It features chainable functionality.
//
////////////////////////////////////////////////////////////////////////////////

// NOTE If we can prevent ALL path errors by validating and cleaning input, we
//      can have an interface without errors ouputs, or at least a choke-point
//      where they would occur; leaving the rest of the API simpler.
// If there is an error, it will be of type *PathError.

type Path string

// TODO: Just maybe these should include the os.File (or not)
type Directory Path
type File Path

type Hash string
type Line string

const (
	LineBreak = "\n"
	Return    = "\r"
)

// TODO: Chown, Chmod, SoftLink, HardLink, Stream Write, Stream Read, Zero-Copy

func ParsePath(path string) Path { return Path(path).Clean() }

func (self Path) String() string { return string(self) }

////////////////////////////////////////////////////////////////////////////////
func (self Path) Directory(directory string) Path {
	return Path(fmt.Sprintf("%s/%s/", self.String(), directory))
}

func (self Path) File(filename string) Path {
	return Path(fmt.Sprintf("%s/%s", Path(self).String(), filename))
}

///////////////////////////////////////////////////////////////////////////////

func (self Directory) Directory(directory string) Path {
	return Path(self).Directory(directory)
}

func (self Directory) String() string { return string(self) }
func (self Directory) Path() Path     { return Path(self) }
func (self Directory) Name() string   { return filepath.Base(Path(self).String()) }

func (self Directory) File(filename string) (File, error) {
	if 0 < len(filename) {
		return File(fmt.Sprintf("%s/%s", Path(self).String(), filename)), nil
	} else {
		if self.Path().IsFile() {
			return File(self), nil
		} else {
			return File(self), fmt.Errorf("error: path does not resolve to file")
		}
	}
}

func (self Directory) List() (list []Path) {
	files, err := ioutil.ReadDir(self.Path().String())
	if err != nil {
		panic(err)
	}
	for _, fileInfo := range files {
		list = append(list, Path(filepath.Join(self.String(), fileInfo.Name())))
	}
	return list
}

func (self Directory) Subdirectories() (list []Directory) {
	for _, file := range self.List() {
		if file.IsDirectory() {
			list = append(list, Directory(file))
		}
	}
	return list
}

func (self Directory) Subfiles() (list []File) {
	for _, file := range self.List() {
		if file.IsFile() {
			list = append(list, File(file))
		}
	}
	return list
}

///////////////////////////////////////////////////////////////////////////////
func (self File) Directory() (Directory, error) {
	if self.Path().IsDirectory() {
		return Directory(self), nil
	} else {
		return Directory(self), fmt.Errorf("error: path does not resolve to directory")
	}
}

func (self File) BaseDirectory() Directory {
	if path, err := filepath.Abs(self.String()); err != nil {
		panic(err)
	} else {
		return Directory(filepath.Dir(path))
	}
}

func (self File) Path() Path       { return Path(self) }
func (self File) Name() string     { return filepath.Base(Path(self).String()) }
func (self File) Basename() string { return self.Name()[0:(len(self.Name()) - len(self.Extension()))] }

// TODO: In a more complete solution, we would also use magic sequence and mime;
// but that would have to be segregated into an interdependent submodule or not
// at all.
func (self File) Extension() string { return filepath.Ext(Path(self).String()) }

// BASIC OPERATIONS ///////////////////////////////////////////////////////////
// NOTE: Create directories if they don't exist, or simply create the
// directory, so we can have a single create for either file or directory.
func (self Path) Move(path string) error {
	if self.Exists() {
		Path(path).Create()
		return self.Remove()
	} else {
		return fmt.Errorf("error: file does not exist")
	}
}

func (self Path) Rename(path string) error {
	baseDirectory := filepath.Dir(path)
	os.MkdirAll(baseDirectory, os.ModePerm)
	return os.Rename(self.String(), path)
}

func (self Path) Remove() error { return os.RemoveAll(self.String()) }

// INFO / META ////////////////////////////////////////////////////////////////
// NOTE: Lets always clean before we get to these so no error is possible.
func (self Path) Metadata() os.FileInfo {
	info, err := os.Stat(self.String())
	if err != nil {
		panic(err)
	}
	return info
}

// TODO: For folders we shuld calculate the size of all the contents recursively
// eventually but for now we just need the file size.
func (self Path) Size() int64 {
	return self.Metadata().Size()
}

func (self Path) UID() int {
	if stat, ok := self.Metadata().Sys().(*syscall.Stat_t); ok {
		return int(stat.Uid)
	} else {
		panic(fmt.Errorf("error: failed to obtain uid of: ", self.String()))
	}
}

func (self Path) GUID() int {
	if stat, ok := self.Metadata().Sys().(*syscall.Stat_t); ok {
		return int(stat.Gid)
	} else {
		panic(fmt.Errorf("error: failed to obtain guid of: ", self.String()))
	}
}

func (self Path) Permissions() os.FileMode {
	return self.Metadata().Mode()
}

// IO /////////////////////////////////////////////////////////////////////////
func (self Path) Create() {
	switch {
	case self.IsDirectory():
		Directory(self).Create()
	case self.IsFile():
		File(self).Create()
	default:
		panic(fmt.Errorf("error: unsupported type"))
	}
}

func (self Directory) Create() {
	if self.Path().IsFile() {
		File(self.Path()).Create()
	} else {
		if !self.Path().Exists() {
			err := os.MkdirAll(self.String(), 0700|os.ModeSticky)
			if err != nil {
				panic(err)
			}
		}
	}
}

func (self File) Create() File {
	if self.Path().IsDirectory() {
		Directory(self.Path()).Create()
	} else {
		path, err := filepath.Abs(self.String())
		if err != nil {
			panic(err)
		}
		Directory(filepath.Dir(path)).Create()
		if !self.Path().Exists() {
			file, err := os.OpenFile(self.String(), os.O_CREATE|os.O_WRONLY, 0640|os.ModeSticky)
			if err != nil && file.Close() != nil {
				panic(err)
			}
		}
	}
	return self
}

func (self File) Overwrite() File {
	if self.Path().IsDirectory() {
		Directory(self.Path()).Create()
	} else {
		path, err := filepath.Abs(self.String())
		if err != nil {
			panic(err)
		}
		Directory(filepath.Dir(path)).Create()
		file, err := os.OpenFile(self.String(), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0640|os.ModeSticky)
		if err != nil && file.Close() != nil {
			panic(err)
		}
	}
	return self
}

// TODO: Maybe ChangePermissions to match the expected Chmod and changeowner
// chown? Right now its Path -> read, and file and directroy are set. Which is
// not exsactly natural
func (self File) Permissions(permissions os.FileMode) File {
	err := os.Chmod(self.String(), permissions)
	if err != nil {
		panic(err)
	}
	return self
}

func (self File) Chmod(permissions os.FileMode) File {
	return self.Permissions(permissions)
}

func (self File) Owner(username string) File {
	u, err := user.Lookup(username)
	var uid int
	if u != nil {
		uid, err = strconv.Atoi(u.Uid)
		if err != nil {
			panic(err)
		}
	} else if err != nil {
		user, idError := user.LookupId(username)
		if idError != nil {
			panic(err)
		}
		uid, err = strconv.Atoi(user.Uid)
		if err != nil {
			panic(err)
		}
	}
	os.Chown(self.String(), uid, self.Path().GUID())
	return self
}

func (self File) Group(guid int) File {
	// TODO: Like above, should be checking the group exists
	os.Chown(self.String(), self.Path().UID(), guid)
	return self
}
func (self File) Chown(uid, guid int) File {
	// TODO: Like above, should be checking the group exists
	os.Chown(self.String(), uid, guid)
	return self
}

// NOTE: In the case of directories, may list contents?
func (self File) Open() *os.File {
	if !self.Path().Exists() {
		self = self.Create()
	}
	openedFile, err := os.Open(self.String())
	if err != nil {
		panic(err)
	}
	return openedFile
}

func (self File) ReadOnly() *os.File {
	if !self.Path().Exists() {
		self = self.Create()
	}
	openedFile, err := os.OpenFile(self.String(), os.O_RDONLY, 0640|os.ModeSticky)
	if err != nil {
		panic(err)
	}
	return openedFile
}

func (self File) WriteOnly() *os.File {
	if !self.Path().Exists() {
		self = self.Create()
	}
	openedFile, err := os.OpenFile(self.String(), os.O_WRONLY|os.O_APPEND, 0640|os.ModeSticky)
	if err != nil {
		panic(err)
	}
	return openedFile
}

func (self File) ReadWrite() *os.File {
	if !self.Path().Exists() {
		self = self.Create()
	}
	openedFile, err := os.OpenFile(self.String(), os.O_RDWR|os.O_APPEND, 0640|os.ModeSticky)
	if err != nil {
		panic(err)
	}
	return openedFile
}

func (self File) Sync() *os.File {
	if !self.Path().Exists() {
		self = self.Create()
	}
	openedFile, err := os.OpenFile(self.String(), os.O_SYNC|os.O_APPEND, 0640|os.ModeSticky)
	if err != nil {
		panic(err)
	}
	return openedFile
}

func (self File) Fd() uintptr { return self.ReadOnly().Fd() }

// TODO: In the future; pass in Byte, Kilobyte, Megabyte, etc
func (self File) Size() int64 { return self.Path().Size() }

// IO: Reads //////////////////////////////////////////////////////////////////

// TODO: Would like the ability to read lines, last 20, first 20, or specific
// line. Then we can do specific line edits with this library, patches, diffs,
// etc.

// NOTE: Simply read ALL bytes
func (self File) Bytes() (output []byte) {
	if self.Path().Exists() {
		output, err := ioutil.ReadFile(self.String())
		if err != nil {
			// TODO: For now we will panic on errors so we can catch any that slip
			// by and squash them or move them downstream to the validation/cleanup
			// chokepoint.
			panic(err)
		}
		return output
	} else {
		panic(fmt.Errorf("error: no file exists"))
	}
}

func (self File) String() string { return string(self.Bytes()) }

// NOTE: This is essentially a Head as is
func (self File) HeadBytes(readSize int) ([]byte, error) {
	var limitBytes []byte
	file := self.Open()

	// TODO: Use seek, seek is really powerful, it lets you jump forward back,
	// etc.

	readBytes, err := io.ReadAtLeast(file, limitBytes, readSize)
	if readBytes != readSize {
		return limitBytes, fmt.Errorf("error: failed to complete read: read ", readBytes, " out of ", readSize, "bytes")
	} else {
		return limitBytes, err
	}
}

// NOTE: This is essentially a Head as is
func (self File) TailBytes(readSize int) ([]byte, error) {
	var data []byte
	file := self.Open()
	bytesRead, err := io.ReadAtLeast(file, data, readSize)
	if bytesRead != readSize {
		return data, fmt.Errorf("error: failed to complete read: read ", bytesRead, " out of ", readSize, "bytes")
	} else {
		return data, err
	}
}

// LINES //////////////////////////////////////////////////////////////////////
// TODO: Add all the code needed for easily abstracting patching, diffs, and
// similar functionality using this library as the backend.
func (self File) Lines() []Line {
	var lines []Line
	for _, line := range strings.Split(self.String(), LineBreak) {
		lines = append(lines, Line(line))
	}
	return lines
}

func (self File) HeadLines(lineCount int) []Line {
	var lines []Line
	for index, line := range strings.Split(self.String(), LineBreak) {
		if index == (lineCount - 1) {
			break
		}
		lines = append(lines, Line(line))
	}
	return lines
}

func (self File) TailLines(lineCount int) []Line {
	var lines []Line
	fileLines := strings.Split(self.String(), LineBreak)
	for index := len(fileLines) - 1; index >= 0; index-- {
		if index == (lineCount - 1) {
			break
		}
		lines = append(lines, Line(fileLines[index]))
	}
	return lines
}

func (self File) Head() []Line { return self.HeadLines(20) }
func (self File) Tail() []Line { return self.TailLines(20) }

///////////////////////////////////////////////////////////////////////////////
type OpenType int

const (
	Append OpenType = iota
	Overwrite
)

// TODO: This is actually quite important, we need to build this so that later
// we will be able to support variable chunk sizes. This is important for later
// streaming protocol plans.

// NOTE: This is a really good concept actually, and building abstraction around
// this like locking subtrees, writing subtrees, etc, would make a fantastic
// foundation for a RESP3 implementation for example; however we need to move
// forward. So we will just make a note about this structure and come back to it
// later
// TODO: My ideal chunking model would actually be a tree.
//       It would reflect a merkle tree, and any subtree could be grabbed using
//       the hash for that subtree. And it would return the offset and length,
//       and ability to read those bytes.

type Chunk struct {
	//Parent        *Chunk
	//ChildChunks   []*Chunk
	//NeighborChunk *Chunk
	Lock   *Lock
	Index  int
	Offset int64
	Length int64
	//Checksum Hash
}

// NOTE After a lot of experimentation it just made sense to by default work
// within the chunking design pattern. Even when its not being used, just have
// that condition be  achunk that is the offset 0, length -1, and a single
// chunk.
type Read struct {
	File   *File
	Atomic bool // Use Locks
	ReadAt time.Time
	Chunks []Chunk
	//Checksum Hash // Root of Merkle
}

func (self *File) Read() *Read {
	return &Read{
		File:   self,
		Atomic: true,
		ReadAt: time.Now(),
		Chunks: []Chunk{
			Chunk{
				Offset: 0,
				Length: self.Size(),
			},
		},
	}
}

// TODO: Not a fan of this, should be using uint's to save memory
func (self *File) ChunkedRead(chunkSize int64) *Read {
	chunkCount := self.Size() / chunkSize
	if (self.Size() % chunkSize) != 0 {
		chunkCount += 1
	}
	var chunks = []Chunk{}
	for index := int64(0); index < chunkCount; index++ {
		chunks = append(chunks, Chunk{
			Offset: (index * chunkSize),
			Length: chunkSize,
		})
	}
	return &Read{
		File:   self,
		Atomic: true,
		ReadAt: time.Now(),
		Chunks: chunks,
	}
}

func (self *File) ParallelRead(chunkCount int64) *Read {
	chunkSize := self.Size() / chunkCount
	if (self.Size() % chunkCount) != 0 {
		chunkSize += 1
	}
	var chunks = []Chunk{}
	for index := int64(0); index < chunkCount; index++ {
		chunks = append(chunks, Chunk{
			Offset: (index * chunkSize),
			Length: chunkSize,
		})
	}
	return &Read{
		File:   self,
		Atomic: true,
		Chunks: chunks,
	}
}

func (self *Read) Path() Path { return self.File.Path() }

// TODO: In the future we use these to read each chunk in parallel using Go
// function and piece them back together using io.Reader's multireader
//func (self *Read) ReadSection() io.Reader {
//	return io.NewSectionReader(self.File.ReadOnly(), self.Offset, self.Length)
//}

//func (self *Read) ReadChunk(chunkIndex int) io.Reader {
//	return io.NewSectionReader(self.File.ReadOnly(), self.ChunkOffset(chunkIndex), self.Chunk)
//}

func (self *Read) Bytes() []byte {

	var chunks []io.Reader
	for _, chunk := range self.Chunks {
		chunks = append(chunks, io.NewSectionReader(self.File.ReadOnly(), chunk.Offset, chunk.Length))
	}

	data := io.MultiReader(chunks...)

	bytes, err := ioutil.ReadAll(data)
	if err != nil {
		panic(err)
	}
	return bytes

	//buffer := bytes.NewBuffer([]byte{})
	//size, err := io.Copy(buffer, data)
	//if err != nil {
	//	panic(err)
	//}
	//return buffer.Bytes()

}

func (self *Read) String() string { return string(self.Bytes()) }

// WRITE //////////////////////////////////////////////////////////////////////
type Write struct {
	File    *File
	Atomic  bool // Use Locks
	WriteAt time.Time
	Chunks  []Chunk
}

func (self *File) Write() *Write {
	return &Write{
		File: self,
		Chunks: []Chunk{
			Chunk{
				Offset: 0,
				Length: self.Size(),
			},
		},
	}
}

func (self *Write) Bytes(data []byte) error {
	file := self.File.WriteOnly()
	_ = len(data)
	err := ioutil.WriteFile(self.File.Path().String(), data, 0644)
	file.Close()
	return err
}

func (self *Write) String(s string) error {
	file := self.File.WriteOnly()
	bytesToWrite := len([]byte(s))
	bytesWritten, err := file.WriteString(s)
	if err != nil {
		return err
	}
	if bytesWritten != bytesToWrite {
		return fmt.Errorf("error: failed write all bytes: ", bytesWritten, " out of ", bytesToWrite)
	}
	return file.Close()
}

// FILE LOCKING ///////////////////////////////////////////////////////////////
// Trying to keep it as simple as possible, but supporting similar functionlaity
// and having similar API to Read/Write IO

type Lock struct {
	Path Path
	//File     *File
	Type     int16
	Timeout  time.Duration
	Atomic   bool // Use Locks
	LockedAt time.Time
	Chunks   []Chunk
}

//func (self *Lock) Chunks() int {
//	chunks := (self.File.Size() / self.Chunk.Length)
//	if (self.File.Size() % self.Chunk) != 0 {
//		return (chunks + 1)
//	} else {
//		return chunks
//	}
//}

func (self *Lock) WriteLock(chunk Chunk) *Lock {
	file := File(self.Path).ReadOnly()
	self.Type = syscall.F_WRLCK
	self.Chunks = append(self.Chunks, chunk)
	err := file.Close()
	if err != nil {
		panic(err)
	}
	return self
}

func (self *Lock) ReadLock(chunk Chunk) *Lock {
	file := File(self.Path).ReadOnly()
	self.Type = syscall.F_RDLCK
	self.Chunks = append(self.Chunks, chunk)
	err := file.Close()
	if err != nil {
		panic(err)
	}
	return self
}

func (self *Lock) Close(chunk Chunk) error {
	file := File(self.Path).ReadOnly()
	err := syscall.FcntlFlock(file.Fd(), syscall.F_SETLK, &syscall.Flock_t{
		Type:   self.Type,
		Whence: int16(os.SEEK_SET),
		Start:  chunk.Offset,
		Len:    chunk.Length,
	})
	if err != nil {
		panic(err)
	}
	return file.Close()
}

func (self *Lock) Open(chunk Chunk) error {
	file := File(self.Path).ReadOnly()
	err := syscall.FcntlFlock(file.Fd(), syscall.F_SETLK, &syscall.Flock_t{
		Type:   syscall.F_UNLCK,
		Whence: int16(os.SEEK_SET),
		Start:  chunk.Offset,
		Len:    chunk.Length,
	})
	if err != nil {
		panic(err)
	}
	return file.Close()
}

// Validation /////////////////////////////////////////////////////////////////
func (self Path) Clean() Path {
	path := filepath.Clean(self.String())
	if filepath.IsAbs(path) {
		return Path(path)
	} else {
		path, _ = filepath.Abs(path)
		return Path(path)
	}
}

// TYPE CHECKS ////////////////////////////////////////////////////////////////
func (self Path) Exists() bool {
	_, err := os.Stat(self.String())
	return !os.IsNotExist(err)
}

func (self Path) IsDirectory() bool {
	return self.Metadata().IsDir()
}

func (self Path) IsFile() bool {
	return self.Metadata().Mode().IsRegular()
}
