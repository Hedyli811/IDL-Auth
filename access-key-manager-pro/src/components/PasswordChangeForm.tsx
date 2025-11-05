import React, { useState } from "react";
import { useAuth } from "./AuthProvider";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Lock, Eye, EyeOff, AlertCircle } from "lucide-react";
import { toast } from "@/hooks/use-toast";

interface PasswordChangeFormProps {
  onPasswordChanged?: () => void;
  isRequired?: boolean; // 是否必须修改密码（403状态）
  isModal?: boolean; // 是否在模态框中显示
  onCancel?: () => void; // 取消按钮的回调函数
}

export const PasswordChangeForm: React.FC<PasswordChangeFormProps> = ({
  onPasswordChanged,
  isRequired = false,
  isModal = false,
  onCancel,
}) => {
  const [oldPassword, setOldPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [showOldPassword, setShowOldPassword] = useState(false);
  const [showNewPassword, setShowNewPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const { changePassword, logout } = useAuth();

  const validatePassword = (password: string) => {
    // 密码至少8位，包含字母和数字
    const minLength = password.length >= 8;
    const hasLetter = /[a-zA-Z]/.test(password);
    const hasNumber = /\d/.test(password);
    
    return {
      isValid: minLength && hasLetter && hasNumber,
      errors: {
        minLength: !minLength,
        hasLetter: !hasLetter,
        hasNumber: !hasNumber,
      }
    };
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);

    // 验证新密码
    const passwordValidation = validatePassword(newPassword);
    if (!passwordValidation.isValid) {
      toast({
        title: "Invalid password",
        description: "Password must be at least 8 characters long and contain both letters and numbers.",
        variant: "destructive",
      });
      setIsLoading(false);
      return;
    }

    // 验证确认密码
    if (newPassword !== confirmPassword) {
      toast({
        title: "Password mismatch",
        description: "New password and confirm password do not match.",
        variant: "destructive",
      });
      setIsLoading(false);
      return;
    }

    try {
      await changePassword(oldPassword, newPassword);
      toast({
        title: "Password changed successfully",
        description: "Your password has been updated successfully.",
      });
      
      // 清空表单
      setOldPassword("");
      setNewPassword("");
      setConfirmPassword("");
      
      // 调用回调函数
      if (onPasswordChanged) {
        onPasswordChanged();
      }
    } catch (error) {
      toast({
        title: "Password change failed",
        description: error.message || "Failed to change password. Please try again.",
        variant: "destructive",
      });
    } finally {
      setIsLoading(false);
    }
  };

  const passwordValidation = validatePassword(newPassword);

  const cardContent = (
    <Card className={`w-full max-w-md shadow-xl ${isModal ? 'shadow-none border-0' : ''}`}>
        <CardHeader className="text-center space-y-2">
          <div className="mx-auto w-12 h-12 bg-blue-600 rounded-full flex items-center justify-center">
            <Lock className="w-6 h-6 text-white" />
          </div>
          <CardTitle className="text-2xl font-bold text-gray-900">
            {isRequired ? "Password Change Required" : "Change Password"}
          </CardTitle>
          <CardDescription className="text-gray-600">
            {isRequired 
              ? "Your password has expired. Please change it to continue."
              : "Update your account password"
            }
          </CardDescription>
          {isRequired && (
            <div className="flex items-center justify-center space-x-2 text-amber-600 bg-amber-50 p-3 rounded-lg">
              <AlertCircle className="w-4 h-4" />
              <span className="text-sm font-medium">Password change is mandatory</span>
            </div>
          )}
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <label className="text-sm font-medium text-gray-700">Current Password</label>
              <div className="relative">
                <Lock className="absolute left-3 top-3 h-4 w-4 text-gray-400" />
                <Input
                  type={showOldPassword ? "text" : "password"}
                  placeholder="Enter current password"
                  value={oldPassword}
                  onChange={(e) => setOldPassword(e.target.value)}
                  className="pl-10 pr-10"
                  required
                />
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  className="absolute right-0 top-0 h-full px-3 py-2 hover:bg-transparent"
                  onClick={() => setShowOldPassword(!showOldPassword)}
                >
                  {showOldPassword ? (
                    <EyeOff className="h-4 w-4 text-gray-400" />
                  ) : (
                    <Eye className="h-4 w-4 text-gray-400" />
                  )}
                </Button>
              </div>
            </div>

            <div className="space-y-2">
              <label className="text-sm font-medium text-gray-700">New Password</label>
              <div className="relative">
                <Lock className="absolute left-3 top-3 h-4 w-4 text-gray-400" />
                <Input
                  type={showNewPassword ? "text" : "password"}
                  placeholder="Enter new password"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  className="pl-10 pr-10"
                  required
                />
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  className="absolute right-0 top-0 h-full px-3 py-2 hover:bg-transparent"
                  onClick={() => setShowNewPassword(!showNewPassword)}
                >
                  {showNewPassword ? (
                    <EyeOff className="h-4 w-4 text-gray-400" />
                  ) : (
                    <Eye className="h-4 w-4 text-gray-400" />
                  )}
                </Button>
              </div>
              
              {/* Password validation feedback */}
              {newPassword && (
                <div className="space-y-1 text-xs">
                  <div className={`flex items-center space-x-1 ${passwordValidation.errors.minLength ? 'text-red-600' : 'text-green-600'}`}>
                    <div className={`w-1.5 h-1.5 rounded-full ${passwordValidation.errors.minLength ? 'bg-red-600' : 'bg-green-600'}`} />
                    <span>At least 8 characters</span>
                  </div>
                  <div className={`flex items-center space-x-1 ${passwordValidation.errors.hasLetter ? 'text-red-600' : 'text-green-600'}`}>
                    <div className={`w-1.5 h-1.5 rounded-full ${passwordValidation.errors.hasLetter ? 'bg-red-600' : 'bg-green-600'}`} />
                    <span>Contains letters</span>
                  </div>
                  <div className={`flex items-center space-x-1 ${passwordValidation.errors.hasNumber ? 'text-red-600' : 'text-green-600'}`}>
                    <div className={`w-1.5 h-1.5 rounded-full ${passwordValidation.errors.hasNumber ? 'bg-red-600' : 'bg-green-600'}`} />
                    <span>Contains numbers</span>
                  </div>
                </div>
              )}
            </div>

            <div className="space-y-2">
              <label className="text-sm font-medium text-gray-700">Confirm New Password</label>
              <div className="relative">
                <Lock className="absolute left-3 top-3 h-4 w-4 text-gray-400" />
                <Input
                  type={showConfirmPassword ? "text" : "password"}
                  placeholder="Confirm new password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  className="pl-10 pr-10"
                  required
                />
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  className="absolute right-0 top-0 h-full px-3 py-2 hover:bg-transparent"
                  onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                >
                  {showConfirmPassword ? (
                    <EyeOff className="h-4 w-4 text-gray-400" />
                  ) : (
                    <Eye className="h-4 w-4 text-gray-400" />
                  )}
                </Button>
              </div>
              {confirmPassword && newPassword !== confirmPassword && (
                <p className="text-xs text-red-600">Passwords do not match</p>
              )}
            </div>

            <div className="space-y-2">
              <Button
                type="submit"
                className="w-full bg-blue-600 hover:bg-blue-700"
                disabled={isLoading || !passwordValidation.isValid || newPassword !== confirmPassword}
              >
                {isLoading ? "Changing password..." : "Change Password"}
              </Button>
              {(isRequired || onCancel) && (
                <Button
                  type="button"
                  variant="outline"
                  className="w-full"
                  onClick={() => {
                    if (onCancel) {
                      onCancel();
                    } else {
                      logout();
                    }
                  }}
                  disabled={isLoading}
                >
                  Exit
                </Button>
              )}
            </div>
          </form>
        </CardContent>
      </Card>
  );

  if (isModal) {
    return cardContent;
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 flex items-center justify-center p-4">
      {cardContent}
    </div>
  );
};
