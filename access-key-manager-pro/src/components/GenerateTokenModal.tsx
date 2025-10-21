import React, { useState, useEffect } from "react";
import { Token } from "./TokenManager";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { toast } from "@/hooks/use-toast";

interface GenerateTokenModalProps {
  isOpen: boolean;
  onClose: () => void;
  onGenerate: (tokenData: Omit<Token, "id" | "createdAt" | "isActive">) => void;
  fetchTokens: () => void;
}

export const GenerateTokenModal: React.FC<GenerateTokenModalProps> = ({
  isOpen,
  onClose,
  onGenerate,
}) => {
  const [applications, setApplications] = useState([]);
  const [selectedComponentId, setSelectedComponentId] = useState(""); // 存储唯一的 component_id
  const [isGenerating, setIsGenerating] = useState(false);

  useEffect(() => {
    const fetchApplications = async () => {
      try {
        const user = JSON.parse(localStorage.getItem("user") || "{}");
        const userId = user.id;
        const token = localStorage.getItem("token");
        const response = await fetch(`/api/user/components`, {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        });
        if (!response.ok) {
          throw new Error("Failed to fetch applications");
        }
        const data = await response.json();
        setApplications(data);
      } catch (error) {
        toast({
          title: "Error",
          description: "Failed to load applications. Please try again.",
          variant: "destructive",
        });
      }
    };
    fetchApplications();
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    // 根据 selectedComponentId 找到完整的应用程序对象
    const selectedApp = applications.find(
      (app) => app.component_id === selectedComponentId
    );

    if (!selectedApp) {
      toast({
        title: "Validation Error",
        description: "Please select an application",
        variant: "destructive",
      });
      return;
    }

    setIsGenerating(true);

    try {
      const user = JSON.parse(localStorage.getItem("user") || "{}");
      const userId = user.user_id;
      // 从选中的应用程序对象中获取 application_id 和 role_id
      const applicationId = selectedApp.application_id;
      const roleId = selectedApp.role_id;
      const token = localStorage.getItem("token");

      const response = await fetch("/api/generate-pat", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          user_id: userId,
          application_id: applicationId,
          role_id: roleId,
        }),
      });

      if (!response.ok) {
        throw new Error("Failed to generate token");
      }

      const data = await response.json();
      const tokenData = {
        application_id: applicationId,
        assoc_api_token: data.pat,
        assoc_expiry_date: data.expires_at,
        role_id: roleId,
        application_name: selectedApp.application_name || "",
        component_name: selectedApp.component_name || "",
      };

      onGenerate(tokenData);
      toast({
        title: "Token Generated Successfully",
        description: `A new token for ${tokenData.component_name} has been created and is ready to use`,
      });

      // Reset form
      setSelectedComponentId(""); // 重置选中的 component_id
    } catch (error) {
      toast({
        title: "Generation Failed",
        description: "Unable to generate token. Please try again.",
        variant: "destructive",
      });
    } finally {
      setIsGenerating(false);
    }
  };

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Generate New Personal Access Token</DialogTitle>
          <DialogDescription>
            Create a new token to access your applications programmatically.
          </DialogDescription>
        </DialogHeader>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-2">
            <Select
              value={selectedComponentId} // 绑定到唯一的 component_id
              onValueChange={setSelectedComponentId} // 更新 selectedComponentId
              required
            >
              <SelectTrigger>
                <SelectValue placeholder="Select an application" />
              </SelectTrigger>
              <SelectContent>
                {applications.map((app) => (
                  <SelectItem key={app.component_id} value={app.component_id}>
                    {" "}
                    {/* 使用唯一的 component_id 作为 value */}
                    <div>
                      <div className="font-medium">
                        <strong>{app.component_name}</strong> -{" "}
                        {app.application_name}{" "}
                      </div>
                      <div className="text-sm text-gray-500">
                        {app.component_desc}
                      </div>
                    </div>
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          {/* <div className="bg-yellow-50 border border-yellow-200 rounded-md p-3">
            <p className="text-sm text-yellow-800">
              <strong>Security Notice:</strong> Store this token securely. It
              won't be shown again after creation.
            </p>
          </div> */}
          <div className="flex justify-end space-x-3 pt-4">
            <Button type="button" variant="outline" onClick={onClose}>
              Cancel
            </Button>
            <Button
              type="submit"
              disabled={isGenerating || !selectedComponentId} // 可以在没有选择时禁用按钮
              className="bg-blue-600 hover:bg-blue-700"
            >
              {isGenerating ? "Generating..." : "Generate Token"}
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
};
