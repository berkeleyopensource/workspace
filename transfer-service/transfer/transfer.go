package transfer

import (
	"errors"
	"net/http"
)

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		http.Error(w, errors.New("bad request").Error(), http.StatusBadRequest)
		return
	case "POST":
		return
	default:
		http.Error(w, errors.New("bad request").Error(), http.StatusBadRequest)
		return
	}
}

func uploadFile(w http.ResponseWriter, r *http.Request) {

	//parse the input file (currently 10 mb)
	r.ParseMultipartForm(10 << 20)

	//file, handler, err := r.FormFile("file")

}

func RegisterRoutes(mux *http.ServeMux) error {

	mux.HandleFunc("/file/upload", uploadHandler)

	return nil
}
