"""
User Permission Model

This table stores granular permissions for each user.
Admin users bypass this table (they have all permissions).

Each user can have different access levels (read/write/delete) 
for each module in the system.

Example:
    permission = UserPermission(
        user_id=2,  # ali
        module=ModuleEnum.ASSET_LIST,
        can_read=True,
        can_write=True,
        can_delete=False
    )
"""

from sqlalchemy import Column, Integer, ForeignKey, Boolean, Enum, UniqueConstraint
from sqlalchemy.orm import relationship
from app.core.database import Base
import enum


class ModuleEnum(str, enum.Enum):
    """
    Available modules in the system
    
    Each module represents a section of the application
    that can have separate permissions.
    """
    
    # Main pages
    DASHBOARD = "dashboard"
    
    # Asset Management sub-modules
    ASSET_REQUIREMENT = "asset_requirement"
    ASSET_LIST = "asset_list"
    ASSET_AUTO_DISCOVERY = "asset_auto_discovery"
    
    # Other main modules
    USER_MANAGEMENT = "user_management"
    AUDITING = "auditing"
    HARDENING = "hardening"
    LOGS = "logs"


class UserPermission(Base):
    """
    User Permission Table
    
    Stores granular permissions for non-admin users.
    Admin users automatically have all permissions (checked in code).
    
    Attributes:
        id: Unique identifier (auto-generated)
        user_id: Reference to users table
        module: Which module this permission applies to
        can_read: Can view/read data in this module
        can_write: Can create/edit data in this module
        can_delete: Can delete data in this module
    
    Business Rules:
        - Admin users bypass this table completely
        - Each user can have one permission record per module
        - Default for new users: dashboard and asset_list have can_read=True
        - Admin must explicitly set permissions when creating user
    
    Relationships:
        user: The user this permission belongs to
    """
    
    __tablename__ = "user_permissions"
    
    # Ensure each user has only one permission record per module
    __table_args__ = (
        UniqueConstraint('user_id', 'module', name='unique_user_module'),
    )
    
    # ====================================
    # Primary Key
    # ====================================
    
    id = Column(
        Integer,
        primary_key=True,
        autoincrement=True,
        comment="Unique identifier for permission record"
    )
    
    # ====================================
    # Foreign Key - User Reference
    # ====================================
    
    user_id = Column(
        Integer,
        ForeignKey('users.id', ondelete='CASCADE'),
        nullable=False,
        index=True,
        comment="Reference to users table"
    )
    
    # ====================================
    # Module
    # ====================================
    
    module = Column(
        Enum(ModuleEnum),
        nullable=False,
        index=True,
        comment="Which module this permission applies to"
    )
    
    # ====================================
    # Permission Flags
    # ====================================
    
    can_read = Column(
        Boolean,
        default=False,
        nullable=False,
        comment="Can view/read data in this module"
    )
    
    can_write = Column(
        Boolean,
        default=False,
        nullable=False,
        comment="Can create/edit data in this module"
    )
    
    can_delete = Column(
        Boolean,
        default=False,
        nullable=False,
        comment="Can delete data in this module"
    )
    
    # ====================================
    # Relationships
    # ====================================
    
    user = relationship(
        "User",
        backref="permissions"
    )
    
    # ====================================
    # Helper Methods
    # ====================================
    
    def __repr__(self):
        perms = []
        if self.can_read:
            perms.append("R")
        if self.can_write:
            perms.append("W")
        if self.can_delete:
            perms.append("D")
        perm_str = "".join(perms) if perms else "None"
        return f"<UserPermission(user_id={self.user_id}, module='{self.module.value}', perms={perm_str})>"
    
    def __str__(self):
        return f"{self.module.value}: read={self.can_read}, write={self.can_write}, delete={self.can_delete}"
    
    def has_any_permission(self):
        """Check if user has any permission for this module"""
        return self.can_read or self.can_write or self.can_delete
    
    def get_permission_dict(self):
        """
        Returns permission as dictionary
        
        Returns:
            dict: Permission details
        
        Example:
            >>> perm.get_permission_dict()
            {
                'module': 'asset_list',
                'can_read': True,
                'can_write': True,
                'can_delete': False
            }
        """
        return {
            'module': self.module.value,
            'can_read': self.can_read,
            'can_write': self.can_write,
            'can_delete': self.can_delete
        }


# ====================================
# Helper Functions
# ====================================

def get_default_permissions():
    """
    Returns default permission settings for new users.
    
    Default: dashboard and asset_list have can_read=True
    All other modules have all permissions False.
    
    Returns:
        list[dict]: List of permission dictionaries
    
    Usage:
        defaults = get_default_permissions()
        for perm in defaults:
            # perm = {'module': ModuleEnum.DASHBOARD, 'can_read': True, ...}
    """
    defaults = []
    
    for module in ModuleEnum:
        perm = {
            'module': module,
            'can_read': False,
            'can_write': False,
            'can_delete': False
        }
        
        # Default: dashboard and asset_list have read access
        if module in [ModuleEnum.DASHBOARD, ModuleEnum.ASSET_LIST]:
            perm['can_read'] = True
        
        defaults.append(perm)
    
    return defaults


def get_all_modules():
    """
    Returns list of all available modules
    
    Returns:
        list[str]: List of module names
    
    Example:
        >>> get_all_modules()
        ['dashboard', 'asset_requirement', 'asset_list', ...]
    """
    return [module.value for module in ModuleEnum]


# ====================================
# Detailed Explanation:
# ====================================
"""
1. Why UniqueConstraint?
   =====================
   Each user can have only ONE permission record per module.
   
   Without constraint:
   user_id=2, module=asset_list, can_read=True
   user_id=2, module=asset_list, can_read=False  # Conflict!
   
   With constraint:
   user_id=2, module=asset_list → Only one record allowed
   

2. Why CASCADE delete?
   ===================
   If a user is deleted:
   - All their permission records should be deleted too
   - No orphaned permission records
   

3. Default Values (False):
   =======================
   All permission flags default to False:
   - Fail-secure approach
   - Must explicitly grant permissions
   - Safer than defaulting to True
   

4. Admin Bypass:
   =============
   Admin users don't need permission records.
   Check in code:
   
   if user.role == "admin":
       return True  # Admin has all permissions
   else:
       # Check permission table
   

5. Practical Usage:
   ================
   # Create permissions for new user
   from app.models.user_permission import UserPermission, ModuleEnum
   
   permission = UserPermission(
       user_id=new_user.id,
       module=ModuleEnum.ASSET_LIST,
       can_read=True,
       can_write=True,
       can_delete=False
   )
   db.add(permission)
   
   
   # Check permission
   perm = db.query(UserPermission).filter(
       UserPermission.user_id == user_id,
       UserPermission.module == ModuleEnum.ASSET_LIST
   ).first()
   
   if perm and perm.can_write:
       # User can write to asset_list
   
   
   # Get all user's permissions
   user = db.query(User).filter(User.id == 2).first()
   for perm in user.permissions:
       print(f"{perm.module.value}: R={perm.can_read}, W={perm.can_write}, D={perm.can_delete}")


6. Integration with Frontend:
   ==========================
   After login, frontend receives user permissions:
   
   {
       "access_token": "...",
       "username": "ali",
       "role": "user",
       "permissions": [
           {"module": "dashboard", "can_read": true, "can_write": false, "can_delete": false},
           {"module": "asset_list", "can_read": true, "can_write": true, "can_delete": false},
           ...
       ]
   }
   
   Frontend uses this to show/hide menu items and buttons.
"""