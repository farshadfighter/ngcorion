"""
User Service with Permission Management
"""
from sqlalchemy.orm import Session
from fastapi import HTTPException, status
from typing import List, Optional

from app.models import User, UserRole
from app.models.user_permission import UserPermission, ModuleEnum, get_default_permissions
from app.models.security_audit_log import log_user_action
from app.schemas.user import UserCreate, UserUpdate
from app.core.security import get_password_hash, verify_password


class UserService:
    """User management service with permission support"""
    
    def __init__(self, db: Session):
        self.db = db
    
    # ==========================================
    # User CRUD Operations
    # ==========================================
    
    def get_all_users(self) -> List[User]:
        """Get all users"""
        return self.db.query(User).all()
    
    def get_user_by_id(self, user_id: int) -> User:
        """Get user by ID with permissions"""
        user = self.db.query(User).filter(User.id == user_id).first()
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"User with id {user_id} not found"
            )
        
        return user
    
    def create_user(self, user_data: UserCreate) -> User:
        """
        Create new user with permissions
        
        If permissions not provided, default permissions are applied:
        - dashboard: read=True
        - asset_list: read=True
        - all others: read=False, write=False, delete=False
        """
        # Check username uniqueness
        existing_user = self.db.query(User).filter(
            User.username == user_data.username
        ).first()
        
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Username '{user_data.username}' already exists"
            )
        
        # Check email uniqueness
        existing_email = self.db.query(User).filter(
            User.email == user_data.email
        ).first()
        
        if existing_email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Email '{user_data.email}' already exists"
            )
        
        # Validate role
        try:
            user_role = UserRole(user_data.role)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid role '{user_data.role}'. Valid roles: admin, manager, user, guest"
            )
        
        # Create user
        new_user = User(
            username=user_data.username,
            email=user_data.email,
            hashed_password=get_password_hash(user_data.password),
            role=user_role,
            is_active=user_data.is_active
        )
        
        self.db.add(new_user)
        self.db.flush()  # Get user ID without committing
        
        # Create permissions (skip for admin - they have all permissions)
        if user_role != UserRole.ADMIN:
            self._create_user_permissions(new_user.id, user_data.permissions)
        
        self.db.commit()
        self.db.refresh(new_user)
        
        # Audit log
        log_user_action(self.db, None, "user.create", new_user.id, 
                       detail=f"Created user '{new_user.username}' with role '{new_user.role.value}'")
        
        print(f"[+] User created: {new_user.username} ({new_user.role.value})")
        
        return new_user
    
    def update_user(self, user_id: int, user_data: UserUpdate, current_user_id: int = None) -> User:
        """Update user and optionally their permissions"""
        user = self.get_user_by_id(user_id)
        
        # Get current user to check their role
        current_user = None
        if current_user_id:
            current_user = self.db.query(User).filter(User.id == current_user_id).first()
        
        # Update username
        if user_data.username is not None:
            existing = self.db.query(User).filter(
                User.username == user_data.username,
                User.id != user_id
            ).first()
            
            if existing:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Username '{user_data.username}' already exists"
                )
            
            user.username = user_data.username
        
        # Update email
        if user_data.email is not None:
            existing = self.db.query(User).filter(
                User.email == user_data.email,
                User.id != user_id
            ).first()
            
            if existing:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Email '{user_data.email}' already exists"
                )
            
            user.email = user_data.email
        
        # Update password
        if user_data.password is not None:
            if current_user_id == user_id:
                if not user_data.current_password:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Current password is required to change your password"
                    )

                if not verify_password(user_data.current_password, user.hashed_password):
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Current password is incorrect"
                    )

            user.hashed_password = get_password_hash(user_data.password)
        
        # Update role
        if user_data.role is not None:
            # SECURITY: Role escalation protection
            old_role = user.role
            new_role_value = user_data.role
            
            # Non-admins cannot change any user's role
            if current_user and current_user.role != UserRole.ADMIN:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Only administrators can change user roles"
                )
            
            # Admins cannot change their own role
            if current_user_id == user_id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="You cannot change your own role"
                )
            
            try:
                new_role = UserRole(new_role_value)
            except ValueError:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid role '{new_role_value}'"
                )
            
            user.role = new_role
            
            # Clean up permissions when role changes
            if old_role != new_role:
                if new_role == UserRole.ADMIN:
                    # Delete all permissions for new admins (they don't need them)
                    self.db.query(UserPermission).filter(UserPermission.user_id == user_id).delete()
                    print(f"[*] Removed permissions for new admin: {user.username}")
                elif old_role == UserRole.ADMIN:
                    # Create default permissions when downgrading from admin
                    self._create_user_permissions(user_id, None)
                    print(f"[*] Created default permissions for downgraded user: {user.username}")
        
        # Update is_active
        if user_data.is_active is not None:
            user.is_active = user_data.is_active
        
        # Update permissions (if provided and user is not admin)
        if user_data.permissions is not None and user.role != UserRole.ADMIN:
            self._update_user_permissions(user_id, user_data.permissions)
        
        self.db.commit()
        self.db.refresh(user)
        
        # Audit logging
        changes = []
        if user_data.username: changes.append(f"username")
        if user_data.email: changes.append(f"email")
        if user_data.password: changes.append(f"password")
        if user_data.is_active is not None: changes.append(f"is_active")
        
        if user_data.role is not None:
            log_user_action(self.db, current_user, "role.change", user_id,
                           detail=f"Changed role to '{user.role.value}'")
        
        if user_data.permissions is not None:
            log_user_action(self.db, current_user, "permission.update", user_id,
                           detail=f"Updated permissions for '{user.username}'")
        
        if changes:
            log_user_action(self.db, current_user, "user.update", user_id,
                           detail=f"Updated {', '.join(changes)} for '{user.username}'")
        
        print(f"[*] User updated: {user.username}")
        
        return user
    
    def delete_user(self, user_id: int, current_user_id: int = None) -> dict:
        """
        Delete user (permissions are deleted automatically via CASCADE)

        Args:
            user_id: ID of the user to delete
            current_user_id: ID of the user performing the deletion (optional)

        Raises:
            HTTPException: If trying to delete self or the last admin
        """
        user = self.get_user_by_id(user_id)
        username = user.username

        # Prevent self-deletion if current_user_id is provided
        if current_user_id and user_id == current_user_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="You cannot delete yourself"
            )

        # Prevent deleting the last admin user
        if user.role == UserRole.ADMIN:
            admin_count = self.db.query(User).filter(
                User.role == UserRole.ADMIN,
                User.is_active == True
            ).count()

            if admin_count <= 1:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Cannot delete the last admin user. Create another admin first."
                )

        self.db.delete(user)
        self.db.commit()
        current_user = None
        if current_user_id:
            current_user = self.db.query(User).filter(User.id == current_user_id).first()
        # Audit log
        log_user_action(self.db, current_user, "user.delete", user_id,
                detail=f"Deleted user '{username}' with role '{user.role.value}'")

        print(f"[-] User deleted: {username}")

        return {
            "success": True,
            "message": f"User '{username}' deleted successfully"
        }
    
    def search_users(self, query: str) -> List[User]:
        """Search users by username or email"""
        return self.db.query(User).filter(
            (User.username.ilike(f"%{query}%")) | 
            (User.email.ilike(f"%{query}%"))
        ).all()
    
    # ==========================================
    # Permission Management
    # ==========================================
    
    def _create_user_permissions(self, user_id: int, permissions_data: Optional[List] = None):
        """
        Create permissions for a user
        
        If permissions_data is None, default permissions are used.
        """
        if permissions_data is None:
            # Use default permissions
            defaults = get_default_permissions()
            for perm in defaults:
                permission = UserPermission(
                    user_id=user_id,
                    module=perm['module'],
                    can_read=perm['can_read'],
                    can_write=perm['can_write'],
                    can_delete=perm['can_delete']
                )
                self.db.add(permission)
        else:
            # Use provided permissions
            for perm_data in permissions_data:
                try:
                    module = ModuleEnum(perm_data.module)
                except ValueError:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Invalid module '{perm_data.module}'"
                    )
                
                permission = UserPermission(
                    user_id=user_id,
                    module=module,
                    can_read=perm_data.can_read,
                    can_write=perm_data.can_write,
                    can_delete=perm_data.can_delete
                )
                self.db.add(permission)
    
    def _update_user_permissions(self, user_id: int, permissions_data: List):
        """
        Update user permissions (replaces all existing permissions)
        """
        # Delete existing permissions
        self.db.query(UserPermission).filter(
            UserPermission.user_id == user_id
        ).delete()
        
        # Create new permissions
        for perm_data in permissions_data:
            try:
                module = ModuleEnum(perm_data.module)
            except ValueError:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid module '{perm_data.module}'"
                )
            
            permission = UserPermission(
                user_id=user_id,
                module=module,
                can_read=perm_data.can_read,
                can_write=perm_data.can_write,
                can_delete=perm_data.can_delete
            )
            self.db.add(permission)
    
    def get_user_permissions(self, user_id: int) -> List[UserPermission]:
        """Get all permissions for a user"""
        return self.db.query(UserPermission).filter(
            UserPermission.user_id == user_id
        ).all()
    
    def check_permission(self, user_id: int, module: str, action: str) -> bool:
        """
        Check if user has specific permission
        
        Args:
            user_id: User ID
            module: Module name (e.g., 'asset_list')
            action: Action type ('read', 'write', 'delete')
        
        Returns:
            bool: True if user has permission
        """
        # Get user to check if admin
        user = self.db.query(User).filter(User.id == user_id).first()
        if not user:
            return False
        
        # Admin has all permissions
        if user.role == UserRole.ADMIN:
            return True
        
        # Check permission table
        try:
            module_enum = ModuleEnum(module)
        except ValueError:
            return False
        
        permission = self.db.query(UserPermission).filter(
            UserPermission.user_id == user_id,
            UserPermission.module == module_enum
        ).first()
        
        if not permission:
            return False
        
        if action == 'read':
            return permission.can_read
        elif action == 'write':
            return permission.can_write
        elif action == 'delete':
            return permission.can_delete
        
        return False
