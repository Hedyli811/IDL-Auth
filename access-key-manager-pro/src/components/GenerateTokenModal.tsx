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
  const [selectedApplicationId, setSelectedApplicationId] = useState("");
  const [selectedRoleId, setSelectedRoleId] = useState("");
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

  // 获取唯一的应用列表
  const getUniqueApplications = () => {
    const uniqueApps = new Map();
    applications.forEach((app) => {
      if (!uniqueApps.has(app.application_id)) {
        uniqueApps.set(app.application_id, {
          application_id: app.application_id,
          application_name: app.application_name,
        });
      }
    });
    return Array.from(uniqueApps.values());
  };

  // 根据选中的应用获取组件列表
  const getComponentsForApplication = () => {
    if (!selectedApplicationId) return [];
    return applications.filter(
      (app) => app.application_id === selectedApplicationId
    );
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!selectedApplicationId || !selectedRoleId) {
      toast({
        title: "Validation Error",
        description: "Please select both application and component",
        variant: "destructive",
      });
      return;
    }

    setIsGenerating(true);

    try {
      const user = JSON.parse(localStorage.getItem("user") || "{}");
      const userId = user.user_id;
      const token = localStorage.getItem("token");

      const response = await fetch("/api/generate-pat", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          user_id: userId,
          application_id: selectedApplicationId,
          role_id: selectedRoleId,
        }),
      });

      if (!response.ok) {
        throw new Error("Failed to generate token");
      }

      const data = await response.json();

      // 找到选中的组件信息
      const selectedComponent = applications.find(
        (app) =>
          app.application_id === selectedApplicationId &&
          app.role_id === selectedRoleId
      );

      const tokenData = {
        application_id: selectedApplicationId,
        assoc_api_token: data.pat,
        assoc_expiry_date: data.expires_at,
        role_id: selectedRoleId,
        application_name: selectedComponent?.application_name || "",
        component_name: selectedComponent?.component_name || "",
      };

      onGenerate(tokenData);
      toast({
        title: "Token Generated Successfully",
        description: `A new token for ${tokenData.component_name} has been created and is ready to use`,
      });

      // Reset form
      setSelectedApplicationId("");
      setSelectedRoleId("");
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
          <div className="space-y-4">
            {/* Application Selection Dropdown */}
            <div className="space-y-2">
              <label className="text-sm font-medium">Select Application</label>
              <Select
                value={selectedApplicationId}
                onValueChange={(value) => {
                  setSelectedApplicationId(value);
                  setSelectedRoleId(""); // Reset component selection
                }}
                required
              >
                <SelectTrigger>
                  <SelectValue placeholder="Select an application" />
                </SelectTrigger>
                <SelectContent>
                  {getUniqueApplications().map((app) => (
                    <SelectItem
                      key={app.application_id}
                      value={app.application_id}
                    >
                      {app.application_name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            {/* Component Selection Dropdown */}
            <div className="space-y-2">
              <label className="text-sm font-medium">Select Component</label>
              <Select
                value={selectedRoleId}
                onValueChange={setSelectedRoleId}
                disabled={!selectedApplicationId}
                required
              >
                <SelectTrigger>
                  <SelectValue
                    placeholder={
                      selectedApplicationId
                        ? "Select a component"
                        : "Please select an application first"
                    }
                  />
                </SelectTrigger>
                <SelectContent>
                  {getComponentsForApplication().map((component) => (
                    <SelectItem
                      key={component.role_id}
                      value={component.role_id}
                    >
                      {component.component_name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
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
              disabled={
                isGenerating || !selectedApplicationId || !selectedRoleId
              }
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
