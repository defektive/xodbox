package load

import (
	"fmt"
	"net/http"
	"sync"
)

func Murder() {
	var wg sync.WaitGroup

	for i := 1; i <= 5000; i++ {
		wg.Add(1)

		go func() {
			defer wg.Done()
			worker(i)
		}()
	}

	wg.Wait()
}

func worker(id int) {

	resp, err := http.Get(fmt.Sprintf("http://localhost:3000/sv?f=/load/%d", id))
	if err != nil {
		//log.Println(err)
		// retry
		worker(id)
		return
	}
	defer resp.Body.Close()

	fmt.Println("Response status:", id, resp.Status)

	//scanner := bufio.NewScanner(resp.Body)
	//for i := 0; scanner.Scan() && i < 5; i++ {
	//	fmt.Println(scanner.Text())
	//}

	//if err := scanner.Err(); err != nil {
	//	//log.Println(err)
	//}
}
