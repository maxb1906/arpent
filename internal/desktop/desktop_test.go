package desktop

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRedirect(t *testing.T) {
	rec := httptest.NewRecorder()
	Redirect(`http://127.0.0.1:1234/login?k=abc&x="y"`).ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	body := rec.Body.String()
	if !strings.Contains(body, `content="0;url=http://127.0.0.1:1234/login?k=abc&amp;x=&#34;y&#34;"`) {
		t.Fatalf("redirection : %s", body)
	}
	if strings.Contains(body, "<script") {
		t.Fatal("pas de script attendu")
	}
}
