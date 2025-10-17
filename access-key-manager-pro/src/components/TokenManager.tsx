import React, { useState, useEffect } from "react";
import { useAuth } from "./AuthProvider";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { TokenList } from "./TokenList";
import { GenerateTokenModal } from "./GenerateTokenModal";
import { PasswordChangeForm } from "./PasswordChangeForm";
import { Plus, LogOut, Key, Lock } from "lucide-react";
import { toast } from "@/hooks/use-toast";

export interface Token {
  application_id: string;
  assoc_api_token: string;
  assoc_expiry_date: string;
  role_id: string;
  application_name: string;
  component_name: string;
}

export const TokenManager: React.FC = () => {
  const { user, logout } = useAuth();
  const [tokens, setTokens] = useState<Token[]>([]);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [isPasswordChangeModalOpen, setIsPasswordChangeModalOpen] =
    useState(false);

  const fetchTokens = async () => {
    try {
      const token = localStorage.getItem("token");

      const response = await fetch(`/api/user/pats?user_id=${user?.user_id}`, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });
      if (response.status === 401) {
        logout();
      }
      if (!response.ok) {
        throw new Error("Failed to fetch tokens");
      }
      const data = await response.json();
      setTokens(data);
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to load tokens. Please try again.",
        variant: "destructive",
      });
    }
  };

  useEffect(() => {
    fetchTokens();
  }, [user]);

  const handleGenerateToken = () => {
    // 在生成新令牌后，重新获取令牌列表
    fetchTokens();
    setIsModalOpen(false);
  };

  const handlePasswordChanged = () => {
    setIsPasswordChangeModalOpen(false);
    toast({
      title: "Password changed successfully",
      description: "Your password has been updated successfully.",
    });
  };

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white border-b border-gray-200 shadow-sm">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-4">
            <div className="flex items-center space-x-3">
              <div className="w-8 h-8 bg-blue-600 rounded-lg flex items-center justify-center">
                <Key className="w-5 h-5 text-white" />
              </div>
              <h1 className="text-2xl font-bold text-gray-900">
                Access Token Management - IDL API
              </h1>
            </div>
            <div className="flex items-center space-x-4">
              <span className="text-sm text-gray-600">
                Welcome, {user?.usersname}
              </span>
              <Button
                variant="outline"
                size="sm"
                onClick={() => setIsPasswordChangeModalOpen(true)}
              >
                <Lock className="w-4 h-4 mr-2" />
                Change Password
              </Button>
              <Button variant="outline" size="sm" onClick={logout}>
                <LogOut className="w-4 h-4 mr-2" />
                Sign out
              </Button>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Token Management Section */}
        <Card>
          <CardHeader>
            <div className="flex justify-between items-center">
              <div>
                <CardTitle>Personal Access Tokens</CardTitle>
                <CardDescription>
                  Manage your access tokens for different applications and
                  services
                </CardDescription>
              </div>
              <Button
                onClick={() => setIsModalOpen(true)}
                className="bg-blue-600 hover:bg-blue-700"
              >
                <Plus className="w-4 h-4 mr-2" />
                Generate New Token
              </Button>
            </div>
          </CardHeader>
          <CardContent>
            <TokenList tokens={tokens} onTokensChange={fetchTokens} />
          </CardContent>
        </Card>
      </main>

      <GenerateTokenModal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        onGenerate={handleGenerateToken}
        fetchTokens={fetchTokens}
      />

      {/* Password Change Modal */}
      {isPasswordChangeModalOpen && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg shadow-xl max-w-md w-full mx-4">
            <PasswordChangeForm
              onPasswordChanged={handlePasswordChanged}
              isRequired={false}
              isModal={true}
            />
            <div className="p-4 border-t">
              <Button
                variant="outline"
                onClick={() => setIsPasswordChangeModalOpen(false)}
                className="w-full"
              >
                Cancel
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
