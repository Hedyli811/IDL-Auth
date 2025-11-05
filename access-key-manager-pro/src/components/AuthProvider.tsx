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
  login: (username: string, password: string) => Promise<string | void>;
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

  // Clear potentially expired auth state on app startup
  useEffect(() => {
    // Clear auth info from localStorage to force re-login and ensure token is fresh
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

      // Try to parse response data (may contain useful info regardless of success/failure)
      let responseData;
      try {
        responseData = await response.json();
      } catch {
        responseData = {};
      }

      // Handle 401 - Password change required
      if (response.status === 423) {
        // Set user state but mark that password change is needed
        setUser({
          user_id: responseData.user_id,
          usersname: responseData.usersname,
          access_token: responseData.access_token || "", // May not have token
        });

        // Store user info
        localStorage.setItem("user", JSON.stringify(responseData));
        if (responseData.access_token) {
          localStorage.setItem("token", responseData.access_token);
        }

        // Set password change required state
        setNeedsPasswordChange(true);
        localStorage.setItem("needsPasswordChange", "true");

        // Don't throw error, allow user to enter password change flow
        // Return message to display to user
        return responseData.message || "Password change required";
      }

      // Handle 403 - User expired
      if (response.status === 403) {
        const errorMessage =
          responseData.message || "Account expired or disabled";
        throw new Error(errorMessage);
      }

      // Handle other error statuses
      if (!response.ok) {
        const errorMessage = responseData.message || "Login failed";
        throw new Error(errorMessage);
      }

      // Handle successful login (200)
      // Update user state
      setUser({
        user_id: responseData.user_id,
        usersname: responseData.usersname,
        access_token: responseData.access_token,
      });

      // Store user info and JWT token
      localStorage.setItem("user", JSON.stringify(responseData));
      localStorage.setItem("token", responseData.access_token);

      // Clear password change requirement
      setNeedsPasswordChange(false);
      localStorage.removeItem("needsPasswordChange");

      // Return success message
      return responseData.message || "Login successful";
    } catch (error) {
      // If error already has message, throw directly; otherwise wrap error
      if (error instanceof Error) {
        throw error;
      }
      throw new Error("Login failed: " + String(error));
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

      // After successful password change, clear password change requirement
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
