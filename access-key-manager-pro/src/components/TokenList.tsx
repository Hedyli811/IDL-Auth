import React, { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { Copy, Eye, EyeOff, Shield, AlertTriangle } from "lucide-react";
import { toast } from "@/hooks/use-toast";
import { format } from "date-fns";

interface Token {
  application_id: string;
  assoc_api_token: string;
  assoc_expiry_date: string;
  role_id: string;
  application_name: string;
  component_name: string;
}

interface TokenListProps {
  tokens: Token[];
  onTokensChange: () => Promise<void>;
}

export const TokenList: React.FC<TokenListProps> = ({ tokens, onTokensChange }) => {
  const [visibleTokens, setVisibleTokens] = useState<Set<string>>(new Set());

  const toggleTokenVisibility = (tokenId: string) => {
    const newVisible = new Set(visibleTokens);
    if (newVisible.has(tokenId)) {
      newVisible.delete(tokenId);
    } else {
      newVisible.add(tokenId);
    }
    setVisibleTokens(newVisible);
  };

  const copyToClipboard = async (token: string, tokenName: string) => {
    try {
      await navigator.clipboard.writeText(token);
      toast({
        title: "Token copied",
        description: `${tokenName} has been copied to clipboard`,
      });
    } catch (error) {
      toast({
        title: "Copy failed",
        description: "Unable to copy token to clipboard",
        variant: "destructive",
      });
    }
  };

  const getTokenStatus = (token: Token) => {
    const now = new Date();
    const expiresAt = new Date(token.assoc_expiry_date);

    if (expiresAt < now) {
      return {
        status: "expired",
        color: "bg-red-100 text-red-800",
        icon: AlertTriangle,
      };
    }

    return {
      status: "active",
      color: "bg-green-100 text-green-800",
      icon: Shield,
    };
  };

  const maskToken = (token: string) => {
    return `${token.substring(0, 8)}${"*".repeat(32)}${token.substring(
      token.length - 8
    )}`;
  };

  if (tokens.length === 0) {
    return (
      <div className="text-center py-12">
        <Shield className="w-12 h-12 text-gray-400 mx-auto mb-4" />
        <h3 className="text-lg font-medium text-gray-900 mb-2">
          No tokens yet
        </h3>
        <p className="text-gray-600">
          Generate your first Personal Access Token to get started
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {tokens.map((token, index) => {
        const { status, color, icon: StatusIcon } = getTokenStatus(token);
        const isVisible = visibleTokens.has(token.application_id);

        return (
          <Card key={index} className="hover:shadow-md transition-shadow">
            <CardContent className="p-6">
              <div className="flex items-start justify-between">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center space-x-3 mb-2">
                    <h3 className="text-lg font-semibold text-gray-900 truncate">
                      {token.application_name}
                    </h3>
                    <Badge className={color}>
                      <StatusIcon className="w-3 h-3 mr-1" />
                      {status}
                    </Badge>
                  </div>

                  <div className="space-y-2">
                    <p className="text-sm text-gray-600">
                      <span className="font-medium">Component:</span>{" "}
                      {token.component_name}
                    </p>

                    <div className="flex items-center space-x-2">
                      <code className="flex-1 px-3 py-2 bg-gray-100 rounded text-sm font-mono text-gray-800 min-w-0 break-all">
                        {isVisible
                          ? token.assoc_api_token
                          : maskToken(token.assoc_api_token)}
                      </code>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() =>
                          toggleTokenVisibility(token.application_id)
                        }
                      >
                        {isVisible ? (
                          <EyeOff className="w-4 h-4" />
                        ) : (
                          <Eye className="w-4 h-4" />
                        )}
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() =>
                          copyToClipboard(
                            token.assoc_api_token,
                            token.application_id
                          )
                        }
                      >
                        <Copy className="w-4 h-4" />
                      </Button>
                    </div>

                    <div className="grid grid-cols-2 gap-4 text-sm text-gray-600">
                      <div>
                        <span className="font-medium">Expires:</span>{" "}
                        {format(
                          new Date(token.assoc_expiry_date),
                          "MMM dd, yyyy"
                        )}
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        );
      })}
    </div>
  );
};
