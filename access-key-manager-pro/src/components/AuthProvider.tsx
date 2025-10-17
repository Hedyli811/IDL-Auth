import React, {
  createContext,
  useContext,
  useState,
  ReactNode,
  useEffect,
} from "react";

interface User {
  user_id: string;
  usersname: string;
  access_token: string;
}

interface AuthContextType {
  user: User | null;
  login: (username: string, password: string) => Promise<void>;
  logout: () => void;
  isAuthenticated: boolean;
  changePassword: (oldPassword: string, newPassword: string) => Promise<void>;
  needsPasswordChange: boolean;
  setNeedsPasswordChange: (needs: boolean) => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
};

interface AuthProviderProps {
  children: ReactNode;
}

export const AuthProvider: React.FC<AuthProviderProps> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [needsPasswordChange, setNeedsPasswordChange] =
    useState<boolean>(false);

  // 应用启动时清理可能过期的认证状态
  useEffect(() => {
    // 清理localStorage中的认证信息，让用户重新登录以确保token是最新的
    localStorage.removeItem("user");
    localStorage.removeItem("token");
    localStorage.removeItem("needsPasswordChange");
    setUser(null);
    setNeedsPasswordChange(false);
  }, []);

  const login = async (username: string, password: string) => {
    try {
      const response = await fetch("/api/login", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ username, password }),
      });

      if (response.status === 403) {
        // 需要修改密码 - 先获取用户信息
        const userData = await response.json();

        // 设置用户状态，但标记需要修改密码
        setUser({
          user_id: userData.user_id,
          usersname: userData.usersname,
          access_token: userData.access_token || "", // 可能没有token
        });

        // 存储用户信息
        localStorage.setItem("user", JSON.stringify(userData));
        if (userData.access_token) {
          localStorage.setItem("token", userData.access_token);
        }

        // 设置需要修改密码的状态
        setNeedsPasswordChange(true);
        localStorage.setItem("needsPasswordChange", "true");

        // 不抛出错误，让用户进入密码修改流程
        return;
      }

      if (!response.ok) {
        throw new Error("Invalid credentials");
      }

      const userData = await response.json();

      // 假设后端返回的数据中包含 access_token 和用户信息
      // 更新用户状态
      setUser({
        user_id: userData.user_id,
        usersname: userData.usersname,
        access_token: userData.access_token,
      });

      // 存储用户信息和JWT令牌
      localStorage.setItem("user", JSON.stringify(userData));
      localStorage.setItem("token", userData.access_token);

      // 清除密码修改要求
      setNeedsPasswordChange(false);
      localStorage.removeItem("needsPasswordChange");
    } catch (error) {
      throw new Error("Login failed: " + error.message);
    }
  };

  const changePassword = async (oldPassword: string, newPassword: string) => {
    try {
      const token = localStorage.getItem("token");
      const response = await fetch("/api/change-password", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          old_password: oldPassword,
          new_password: newPassword,
        }),
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.message || "Failed to change password");
      }

      // 密码修改成功后，清除密码修改要求
      setNeedsPasswordChange(false);
      localStorage.removeItem("needsPasswordChange");
    } catch (error) {
      throw new Error("Password change failed: " + error.message);
    }
  };

  const logout = () => {
    setUser(null);
    setNeedsPasswordChange(false);
    localStorage.removeItem("user");
    localStorage.removeItem("tokens");
    localStorage.removeItem("needsPasswordChange");
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        login,
        logout,
        isAuthenticated: !!user,
        changePassword,
        needsPasswordChange,
        setNeedsPasswordChange,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};
