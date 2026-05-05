# Frontend Guide: User Password Changes

## Backend Rule

When the authenticated user changes their own password through user management, the backend now requires their current password.

- Endpoint: `PUT /api/users/{user_id}`
- Auth: Bearer token
- Required only for self password changes: `current_password`
- Still required for password changes: `password`
- Admin/user-management resets for another user do not require the target user's current password.

## Request Examples

### Self Password Change

```json
{
  "password": "newSecurePassword123",
  "current_password": "oldSecurePassword123"
}
```

You can include other editable fields in the same request if needed:

```json
{
  "username": "alice",
  "email": "alice@example.com",
  "password": "newSecurePassword123",
  "current_password": "oldSecurePassword123",
  "permissions": [
    {
      "module": "dashboard",
      "can_read": true,
      "can_write": false,
      "can_delete": false
    }
  ]
}
```

### Admin Resetting Another User

```json
{
  "password": "temporaryPassword123"
}
```

## Frontend Implementation

1. Detect self-edit:
   - Compare logged-in user id with the edited user id.
   - If the ids match and the new password field is not empty, show a `Current password` input.

2. Validate before submit:
   - If editing self and `password` has a value, require `current_password`.
   - Do not send `current_password` when the password is not changing.

3. Build payload:
   - Keep existing behavior of omitting empty `password`.
   - Add `current_password` only when changing the authenticated user's own password.

```js
if (formData.password) {
  updateData.password = formData.password;

  if (authUser.id === user.id) {
    updateData.current_password = formData.current_password;
  }
}
```

## Error Handling

Show these backend validation messages near the password fields:

- `400` + `Current password is required to change your password`
- `401` + `Current password is incorrect`

Recommended UX:

- Keep the modal open on these errors.
- Clear only the `current_password` field after an incorrect current password.
- Do not clear the new password field unless the user cancels.
