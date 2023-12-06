package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"time"

	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"github.com/annetutil/gnetcli/internal/gvendor"
)

const asciiLine = " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`abcdefghijklmnopqrstuvwxyz{|}~"
const unicodeLine = "❶❷❸❹❺❻❼❽❾❿➀➁➂➃➄➅➆➇➈➉"
const asciiBinaryLine = "some\x00data"
const hello = "Welcome to gvendor CLI."

func main() {
	scenario := flag.String("scenario", "", "Scenario to play. Available: unicode, smalldata, smalldata_with_binary, hugedata_10000, hugedata_chunk_100_20000, bunch_cmd_1000")
	debug := flag.Bool("debug", false, "Set debug log level")
	host := flag.String("host", "localhost", "Server host")
	port := flag.Int("port", 2222, "Server port")
	flag.Parse()
	logConfig := zap.NewProductionConfig()
	if *debug {
		logConfig = zap.NewDevelopmentConfig()
	}
	logger := zap.Must(logConfig.Build())
	var sc []gvendor.Action
	switch *scenario {
	case "unicode":
		sc = makeHugeDataChunkedDialog(0, 1, unicodeLine, false)
	case "smalldata":
		sc = makeHugeDataChunkedDialog(0, 1, asciiLine, false)
	case "smalldata_with_binary":
		sc = makeHugeDataChunkedDialog(0, 1, asciiBinaryLine, false)
	case "hugedata_10000":
		sc = makeHugeDataChunkedDialog(0, 10000, asciiLine, false)
	case "hugedata_chunk_100_20000":
		sc = makeHugeDataChunkedDialog(100, 20000, asciiLine, false)
	case "hugedata_chunk_20000_per_byte_write":
		sc = makeHugeDataChunkedDialog(0, 20000, asciiLine, true)
	case "bunch_cmd_1000":
		sc = makeBunchCmdsDialog(1000)
	default:
		panic(fmt.Errorf("unknown scenario %s", *scenario))
	}
	addr := fmt.Sprintf("%s:%d", *host, *port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		panic(err)
	}
	sshServer, err := gvendor.New(sc, gvendor.WithLogger(logger), gvendor.WithListener(listener))
	if err != nil {
		panic(err)
	}

	ctx := context.Background()
	wg, wCtx := errgroup.WithContext(ctx)
	wg.Go(func() error {
		err := sshServer.Run(wCtx)
		if err != nil {
			return err
		}
		return nil
	})

	logger.Warn("listening on", zap.String("addr", addr))
	err = wg.Wait()
	panic(err)
}

func makeHugeDataChunkedDialog(wait time.Duration, linesCount int, line string, perByteWrite bool) []gvendor.Action {
	prompt := "login@ghost> "
	sc := []gvendor.Action{
		gvendor.SendLine(hello)}
	sc = append(sc, next(prompt, "show data")...)
	sc = append(sc,
		gvendor.Send(prompt),
		gvendor.ExpectLine("show data"),
	)
	for i := 0; i < linesCount; i++ {
		sc = append(sc, gvendor.SendBytes([]byte(line), wait, perByteWrite))
	}
	sc = append(sc, gvendor.Send("\r\n"))
	sc = append(sc, next(prompt, "quit")...)
	sc = append(sc,
		gvendor.Send(prompt),
		gvendor.ExpectLine("quit"),
		gvendor.Close(),
	)
	return sc
}

func next(prompt, next string) []gvendor.Action {
	return []gvendor.Action{
		gvendor.Send(prompt),
		gvendor.ExpectLine("next"),
		gvendor.SendLine(next),
	}
}

func makeBunchCmdsDialog(count int) []gvendor.Action {
	prompt := "login@ghost> "
	sc := []gvendor.Action{}
	for i := 0; i < count; i++ {
		sc = append(sc, next(prompt, "next")...)
	}
	sc = append(sc, next(prompt, "quit")...)
	return sc
}
