package httpx

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func Test_compileEmbeddedPayloadTemplates(t *testing.T) {
	type args struct {
		fsToCheck fs.FS
	}
	tests := []struct {
		name    string
		args    args
		want    []*Payload
		wantErr bool
	}{
		{
			name: "Embedded payloads templates compile",
			args: args{
				&embeddedSeedFS,
			},
			want:    nil,
			wantErr: false,
		},
		{
			name: "Example payloads templates compile",
			args: args{
				os.DirFS(filepath.Join("examples")),
			},
			want:    nil,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getPayloadsFromFS(tt.args.fsToCheck)
			if (err != nil) != tt.wantErr {
				t.Errorf("getPayloadsFromFS() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			//if !reflect.DeepEqual(got, tt.want) {
			//	t.Errorf("getPayloadsFromFS() got = %v, want %v", got, tt.want)
			//}

			for _, payload := range got {
				_, err := payload.BodyTemplate()
				if err != nil {
					t.Errorf("unable to compile body template payload = %s error = %v", payload.Name, err)
				}

				// make sure we dont panic :D
				payload.HeaderTemplates()
				payload.StatusTemplate()
			}
		})
	}
}
