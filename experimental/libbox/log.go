//go:build darwin || linux || windows

package libbox

import (
	"archive/zip"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"time"

	"filippo.io/age"
)

type crashReportMetadata struct {
	reportMetadata
	CrashedAt       string `json:"crashedAt,omitempty"`
	SignalName      string `json:"signalName,omitempty"`
	SignalCode      string `json:"signalCode,omitempty"`
	ExceptionName   string `json:"exceptionName,omitempty"`
	ExceptionReason string `json:"exceptionReason,omitempty"`
}

func archiveCrashReport(path string, crashReportsDir string) {
	content, err := os.ReadFile(path)
	if err != nil || len(content) == 0 {
		return
	}

	info, _ := os.Stat(path)
	crashTime := time.Now().UTC()
	if info != nil {
		crashTime = info.ModTime().UTC()
	}

	initReportDir(crashReportsDir)
	destPath, err := nextAvailableReportPath(crashReportsDir, crashTime)
	if err != nil {
		return
	}
	initReportDir(destPath)

	writeReportFile(destPath, "go.log", content)
	metadata := crashReportMetadata{
		reportMetadata: baseReportMetadata(),
		CrashedAt:      crashTime.Format(time.RFC3339),
	}
	writeReportMetadata(destPath, metadata)
	os.Remove(path)
	copyConfigSnapshot(destPath)
}

func configSnapshotPath() string {
	return filepath.Join(sBasePath, "configuration.json")
}

func saveConfigSnapshot(configContent string) {
	snapshotPath := configSnapshotPath()
	os.WriteFile(snapshotPath, []byte(configContent), 0o666)
	chownReport(snapshotPath)
}

func redirectStderr(path string) error {
	crashReportsDir := filepath.Join(sWorkingPath, "crash_reports")
	archiveCrashReport(path, crashReportsDir)
	archiveCrashReport(path+".old", crashReportsDir)

	outputFile, err := os.Create(path)
	if err != nil {
		return err
	}
	if runtime.GOOS != "android" && runtime.GOOS != "windows" {
		err = outputFile.Chown(sUserID, sGroupID)
		if err != nil {
			outputFile.Close()
			os.Remove(outputFile.Name())
			return err
		}
	}

	err = debug.SetCrashOutput(outputFile, debug.CrashOptions{})
	if err != nil {
		outputFile.Close()
		os.Remove(outputFile.Name())
		return err
	}
	_ = outputFile.Close()
	return nil
}

func CreateZipArchive(sourcePath string, destinationPath string, encrypt bool) error {
	sourceInfo, err := os.Stat(sourcePath)
	if err != nil {
		return err
	}
	if !sourceInfo.IsDir() {
		return os.ErrInvalid
	}

	destinationFile, err := os.Create(destinationPath)
	if err != nil {
		return err
	}
	defer func() {
		_ = destinationFile.Close()
	}()

	var archiveWriter io.Writer = destinationFile
	var encryptedWriter io.WriteCloser
	if encrypt {
		const reportEncryptionRecipient = "age1pq197e22fqk25pmeq23zu209zn5l85tr4h450s5kdknldpxanznufgkwqj5ef03033q290pls9hy3990cv5dd8w436lje4k2pkzp34mc40mwxe3tsxugpmgcx65lrgv9drnc0uw30xetdr25a2fs6p4uxyxd46kk4hw8p97cpxxh63t3y2gevcv83dak9k3256fz89k99vhe7l4kvcgzqu297c5v9m3xtexp9dz0vj29plerczjmj4nr24c3f3wca9ewjdm67w8z43fg7ncekcervpez9k53zr6rk5c7e03xjyc8wazs5lkcksqemegjkmy8u4meplftj0kw79ds8mfkct8zlcp2zykjwy4ugzj8uyrcjvndg6szpyy5vm828zwvc39grh6yk07fxhvsw5sckeqq4d2t5j44gujkj0nuu4jx9ma6art33940s78kulgcyjgw92ry34xjclzk85pzd329ssk03p4alkt8zx833jsgawsvfk2lzn8f72nlen2kwhwvy32fw5eev60fhz2j8jt5dhgrsxzmw8lw89jy36qylz92zchw75r30zdamqx2feuztf4jqcc9ngprjnnys9jd3nxf2k3wys3yfr6fdsdrvwxehzze74ur08fwuumjs68pqp3t6e9wazgq0z6dp7y2ggw9zq8xv9vdsnh0gsptf2q79qg926qqz56l4atvcp54zj6vp4pq7z2n5m3yk05n839d8khkuqknz3h7l2c4gmkrlyzy2lpsvne6vgx56u9pvhcjluls5c0quywv7rmj0ph30rnwrukngfjrnysv3950np4vy09kthsv9ndwsvzypc2nf6eqxjyga0ae3ew4pwtwgu6xh6udty40z9xkfa0x42c8ya9jguzcmruc23vywj9qw0x48qf3ru27cd5na9r09q74wgj5qpwfty265s9nf7syvrey42wtft7qcpct7z40mjhs9vuvj4gefderdv9d9t4caa38wkhjpyv23qw8ev37243w5n4whgj4rr3azm4avgxar438pey303cce6n8f95s4t4zf6ej3uhn32aqyn9na9tmtvc92nys2rzzjdrz2kgrc9lz5qy7asz566m9tmrgwpqdpppmuz4le5kfqz2qatsdz44tyze5d69pwvtn6w7cz9vjygw477tup3f0uakjql4kdpjka8acvjs904nnt52vtnawac7sz4etq9d43j83r6vy5ddfdgqyeyp6wf8gea3j70pvdll3zf66fe7ew2yjutuu0rsheglxh0tf2zgecgwc6jsprtpq342xnyrtfgeksqdquqndfjt5va5cl6exstqd69w24vm3wu4s4ymkazfxjpcs56844z49g0udhxtg22g7lph7jau3cggp3vtnssncdk3yqqdh5qtq3vq6hd5227lj9y8gz2wd4ge906hlv4ywd9h9jvg8d6ce7tu4wkzpj0pyulc3jm8jesvr5fk923swjxqfvzvju3wu4z9maneaxwp83ah33w50y43wsqlvuc5a4tuheqrkfk3nf333skc0xrzuysf5rxmd0c20n6shjafx2ftru7238c6tmghrv3fed7xchzjc3f3ecgc3ejp5vc8rw6heejzqy6mkakk2hgvpdc2ywfg5prnz27za20mfyc8zn8mzp6pdks8glxvzg24fuadqemn2dr7r57f5e7y5c5p936v3j7lye8vq2nw04xvttemsfwucunwuukthqt7ejnjvz4yyqmc30w2qyre6em8jgzsnyxkjwumqqrvp2jvw6m88fkgzweq8dv38vqxsdgapy6ydajs3u73sv9jv8t04fpf2ceha305hkswx7ealew46pll8sd3wj4xu5a79mua60efdjyc38u8u8tw47gn06hljdkfxvguy7kky6lg6ljmqk9qa7fqfjjpjv9mdqh0kr6q"
		var recipient *age.HybridRecipient
		recipient, err = age.ParseHybridRecipient(reportEncryptionRecipient)
		if err != nil {
			return err
		}
		encryptedWriter, err = age.Encrypt(destinationFile, recipient)
		if err != nil {
			return err
		}
		archiveWriter = encryptedWriter
	}

	zipWriter := zip.NewWriter(archiveWriter)

	rootName := filepath.Base(sourcePath)
	err = filepath.WalkDir(sourcePath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		relativePath, err := filepath.Rel(sourcePath, path)
		if err != nil {
			return err
		}
		if relativePath == "." {
			return nil
		}

		archivePath := filepath.ToSlash(filepath.Join(rootName, relativePath))
		if d.IsDir() {
			_, err = zipWriter.Create(archivePath + "/")
			return err
		}

		fileInfo, err := d.Info()
		if err != nil {
			return err
		}
		header, err := zip.FileInfoHeader(fileInfo)
		if err != nil {
			return err
		}
		header.Name = archivePath
		header.Method = zip.Deflate

		writer, err := zipWriter.CreateHeader(header)
		if err != nil {
			return err
		}

		sourceFile, err := os.Open(path)
		if err != nil {
			return err
		}

		_, err = io.Copy(writer, sourceFile)
		closeErr := sourceFile.Close()
		if err != nil {
			return err
		}
		return closeErr
	})
	if err != nil {
		_ = zipWriter.Close()
		if encryptedWriter != nil {
			_ = encryptedWriter.Close()
		}
		return err
	}

	err = zipWriter.Close()
	if err != nil {
		if encryptedWriter != nil {
			_ = encryptedWriter.Close()
		}
		return err
	}
	if encryptedWriter != nil {
		return encryptedWriter.Close()
	}
	return nil
}
