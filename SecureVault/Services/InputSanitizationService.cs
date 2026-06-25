using System.Text;
using System.Text.RegularExpressions;
using System.Web;

namespace SecureVault.Services;

/// <summary>
/// Service for sanitizing and validating user input to prevent XSS and injection attacks.
/// </summary>
public class InputSanitizationService
{
    private readonly ILogger<InputSanitizationService> _logger;

    public InputSanitizationService(ILogger<InputSanitizationService> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Sanitizes a string by trimming whitespace and removing potentially harmful HTML/JavaScript.
    /// </summary>
    public string Sanitize(string? input)
    {
        if (string.IsNullOrEmpty(input))
            return string.Empty;

        // Trim whitespace
        string result = input.Trim();

        // HTML encode to prevent XSS
        result = HtmlEncode(result);

        return result;
    }

    /// <summary>
    /// Trims whitespace from input while preserving internal spaces.
    /// </summary>
    public string Trim(string? input)
    {
        return string.IsNullOrEmpty(input) ? string.Empty : input.Trim();
    }

    /// <summary>
    /// HTML encodes a string to prevent XSS attacks.
    /// </summary>
    public string HtmlEncode(string? input)
    {
        if (string.IsNullOrEmpty(input))
            return string.Empty;

        return HttpUtility.HtmlEncode(input);
    }

    /// <summary>
    /// Validates that input does not contain suspicious patterns.
    /// Returns true if input is safe, false if potentially dangerous.
    /// </summary>
    public bool IsValidInput(string? input)
    {
        if (string.IsNullOrEmpty(input))
            return true;

        // Patterns to block: script tags, event handlers, SQL injections, etc.
        var dangerousPatterns = new[]
        {
            @"<script", // Script tags
            @"javascript:", // JavaScript protocol
            @"on\w+\s*=", // Event handlers (onclick, onload, etc.)
            @"<iframe", // iframes
            @"<object", // Object tags
            @"<embed", // Embed tags
            @"eval\s*\(", // eval calls
        };

        var lowerInput = input.ToLowerInvariant();
        foreach (var pattern in dangerousPatterns)
        {
            if (Regex.IsMatch(lowerInput, pattern, RegexOptions.IgnoreCase))
            {
                _logger.LogWarning("Potentially dangerous pattern detected in input: {Pattern}", pattern);
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Sanitizes a string and validates it in one step.
    /// Throws an exception if input contains dangerous patterns.
    /// </summary>
    public string SanitizeAndValidate(string? input)
    {
        if (string.IsNullOrEmpty(input))
            return string.Empty;

        if (!IsValidInput(input))
        {
            throw new ArgumentException("Input contains potentially dangerous content.", nameof(input));
        }

        return Sanitize(input);
    }

    /// <summary>
    /// Safely decodes HTML-encoded strings for display purposes.
    /// </summary>
    public string HtmlDecode(string? input)
    {
        if (string.IsNullOrEmpty(input))
            return string.Empty;

        return HttpUtility.HtmlDecode(input);
    }
}
