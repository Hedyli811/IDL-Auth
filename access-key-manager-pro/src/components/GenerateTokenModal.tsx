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
  fetchTokens,
}) => {
  const [applications, setApplications] = useState([]);
  const [selectedApplication, setSelectedApplication] = useState("");
  const [isGenerating, setIsGenerating] = useState(false);

  useEffect(() => {
    const fetchApplications = async () => {
      try {
        const user = JSON.parse(localStorage.getItem("user") || "{}");
        const userId = user.id;
        const token = localStorage.getItem("token");

        const response = await fetch(
          `http://localhost:5000/user/components?user_id=${userId}`,
          {
            headers: {
              'Authorization': `Bearer ${token}`,
            },
          }
        );

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

    if (!selectedApplication) {
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
      const applicationId = applications.find(
        (app) => app.role_id === selectedApplication
      )?.application_id;
      const roleId = selectedApplication;
      const token = localStorage.getItem("token"); 
      const response = await fetch("http://localhost:5000/generate-pat", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          'Authorization': `Bearer ${token}`,
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
        name:
          applications.find((app) => app.role_id === selectedApplication)
            ?.component_name || selectedApplication,
        application:
          applications.find((app) => app.role_id === selectedApplication)
            ?.component_name || selectedApplication,
        token: data.pat,
        expiresAt: data.expires_at, 
      }; 
 

      onGenerate(tokenData);  
      toast({
        title: "Token Generated Successfully",
        description: `A new token for ${tokenData.name} has been created and is ready to use`,
      });

      // Reset form
      setSelectedApplication("");
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
              value={selectedApplication}
              onValueChange={setSelectedApplication}
              required
            >
              <SelectTrigger>
                <SelectValue placeholder="Select an application" />
              </SelectTrigger>
              <SelectContent>
                {applications.map((app) => (
                  <SelectItem key={app.component_id} value={app.role_id}>
                    <div>
                      <div className="font-medium">{app.component_name}</div>
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
              disabled={isGenerating}
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
 