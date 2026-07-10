package httpx

import (
	"encoding/json"
	"net/http"

	"github.com/defektive/xodbox/pkg/model"
)

// requireAdmin wraps requireAuth and additionally requires the admin role.
func (a *adminAuth) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return a.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		if u := userFromContext(r.Context()); u == nil || !u.IsAdmin() {
			writeErr(w, http.StatusForbidden, "admin role required")
			return
		}
		next(w, r)
	})
}

func (a *adminAuth) handleUsers(w http.ResponseWriter, r *http.Request) {
	rows := model.ListUsers()
	out := make([]userView, 0, len(rows))
	for i := range rows {
		out = append(out, toUserView(&rows[i]))
	}
	writeJSON(w, http.StatusOK, out)
}

type createUserRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

func (a *adminAuth) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req createUserRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxLoginBody)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request")
		return
	}
	u, err := model.CreateUser(req.Username, req.Password, req.Role)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, toUserView(u))
}

func (a *adminAuth) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	me := userFromContext(r.Context())
	if me != nil && me.ID == id {
		writeErr(w, http.StatusBadRequest, "cannot delete your own account")
		return
	}
	target, err := model.UserByID(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	if target.IsAdmin() && model.CountAdmins() <= 1 {
		writeErr(w, http.StatusBadRequest, "cannot delete the last admin")
		return
	}
	if err := model.DeleteUser(id); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type passwordRequest struct {
	Password string `json:"password"`
}

// handleResetPassword lets an admin set another user's password and revokes
// that user's active sessions.
func (a *adminAuth) handleResetPassword(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	target, err := model.UserByID(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	var req passwordRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxLoginBody)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request")
		return
	}
	if err := target.SetPassword(req.Password); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	model.DeleteUserSessions(target.ID)
	w.WriteHeader(http.StatusNoContent)
}

type changePasswordRequest struct {
	Current string `json:"current"`
	New     string `json:"new"`
}

// handleAccountPassword lets the authenticated user change their own password
// after re-entering the current one. All other sessions are revoked; the
// current browser session is re-issued so the caller stays logged in.
func (a *adminAuth) handleAccountPassword(w http.ResponseWriter, r *http.Request) {
	me := userFromContext(r.Context())
	var req changePasswordRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxLoginBody)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request")
		return
	}
	if _, err := model.Authenticate(me.Username, req.Current); err != nil {
		writeErr(w, http.StatusUnauthorized, "current password is incorrect")
		return
	}
	if err := me.SetPassword(req.New); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	model.DeleteUserSessions(me.ID)

	// Re-issue a session for the current browser (cookie auth only).
	if _, err := r.Cookie(sessionCookie); err == nil {
		if token, terr := model.NewSession(me.ID, model.DefaultSessionTTL, r.UserAgent(), peerIP(r)); terr == nil {
			a.setSessionCookie(w, r, token)
		}
	}
	w.WriteHeader(http.StatusNoContent)
}
