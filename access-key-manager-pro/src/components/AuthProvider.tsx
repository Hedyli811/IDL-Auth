import React, { createContext, useContext, useState, ReactNode } from "react";

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
  const [user, setUser] = useState<User | null>(() => {
    const savedUser = localStorage.getItem("user");
    return savedUser ? JSON.parse(savedUser) : null;
  });

  const login = async (username: string, password: string) => {
    try {
      const response = await fetch("http://localhost:5000/login", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ username, password }),
      });

      if (!response.ok) {
        throw new Error("Invalid credentials");
      }

      const userData = await response.json();

      // 假设后端返回的数据中包含 access_token 和用户信息 
      console.log(userData)
      // 更新用户状态
      setUser({
        id: userData.user_id, 
        usersname: userData.usersname, 
        access_token: userData.access_token,
      });
      console.log(user)

      // 存储用户信息和JWT令牌
      localStorage.setItem("user",  JSON.stringify(userData));
      localStorage.setItem("token", userData.access_token);
      console.log(localStorage.getItem("user"))
    } catch (error) {
      throw new Error("Login failed: " + error.message);
    }
  };

  const logout = () => {
    setUser(null);
    localStorage.removeItem("user");
    localStorage.removeItem("tokens");
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        login,
        logout,
        isAuthenticated: !!user,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};
