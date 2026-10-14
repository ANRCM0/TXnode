package vless

import (
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
)

func (h *Inbound) UpdateUsers(users []option.VLESSUser) error {
	h.usersMu.Lock()
	defer h.usersMu.Unlock()
	users = append([]option.VLESSUser(nil), users...)
	h.service.UpdateUsers(common.MapIndexed(users, func(index int, user option.VLESSUser) authenticatedUser {
		return authenticatedUser{Index: index, Name: user.Name, UUID: user.UUID}
	}), common.Map(users, func(user option.VLESSUser) string { return user.UUID }), common.Map(users, func(user option.VLESSUser) string { return user.Flow }))
	h.users = users
	return nil
}
