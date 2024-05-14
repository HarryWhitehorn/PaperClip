# Paperclip

## Abstract

This project attempts to define and implement networking tools including a lightweight protocol for use with game technology and an account and game session management server.

## 1 Introduction

### 1.1 Problem Description

When creating a multiplayer game, every developer must integrate a few key features. Even though every multilayer game shares these same key features, a developer must build these from scratch. This is time consuming and means that a developer is limited in the amount of initial development they can put into their game. Though some implementations of a custom networking protocol exist (described in the Literature Review [3]), no implementation provides both a variety of rich-features with full flexibility in when/which features are used.

### 1.2 Objectives

#### 1.2.1 Primary Objectives

1. Create a scalable system for managing user accounts and inter-account interactions including matchmaking and friends.
2. Create a custom UDP protocol that implements key features required for game communication missing from vanilla UDP. This includes features to improve reliability and security.

#### 1.2.2 Secondary Objectives

The secondary objectives are split into sub objectives as follows:

```{.include}
docs/objectives/objectives.tex
```

### 1.3 Beneficiaries

The project is intended to be used by game developers when programming networking for multiplayer games.

### 1.4 Assumptions and limitations

Originally, the project focused primarily on a rich-feature account and game session server however, its scope was largely decreased as greater emphasis was put on the implementation of the UDP protocol. Additionally, the sub-objective of creating a real-time game demo was not completed due to time constraints. Similarly, the depth of the turn-based demo was minimized.

<!-- ## 2 Output Summary -->

```{.include shift-heading-level-by=1}
docs\outputs\outputs.md
```

<!-- ## 3 Literature Review -->

```{.include shift-heading-level-by=1}
docs\lit_rev\lit_rev.md
```

<!-- ## 4 Method -->

```{.include shift-heading-level-by=1}
docs\method.md
```

<!-- ## 5 Results -->

```{.include shift-heading-level-by=1}
docs\results.md
```

<!-- ## 6 Conclusion -->

```{.include shift-heading-level-by=1}
docs\conclusion.md
```

<!-- ## 7 Glossary -->

```{.include shift-heading-level-by=1}
docs\glossary.md
```

## 8 References

::: {#refs}
:::

## 9 Appendices

<!-- ### 9.1 PDD -->
```{.include shift-heading-level-by=2}
docs\PDD\V2 Project Definition Document.md
```

---

<!-- ### 9.2 Deployment Guide -->
```{.include shift-heading-level-by=2}
docs\deployment.md
```

---

<!-- ### 9.3 Package -->
```{.include shift-heading-level-by=2}
docs\package.md
```

---

<!-- ### Packet Specification -->

```{.include shift-heading-level-by=2}
docs\packet_spec\packet_spec.md
```

---

<!-- ### API Specification -->

```{.include shift-heading-level-by=2}
docs\api_spec\api_spec.md
```

---

### 9.6 ERD Diagram

![Database Models ERD](docs\ERD\ERD.jpg)

---
