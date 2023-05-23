# Hierarchical derivation of symmetric keys

Golang SLIP-0021 implementation according to the https://github.com/satoshilabs/slips/blob/master/slip-0021.md

## Example

```go
    package main
    
    import (
        "encoding/hex"
        "fmt"

        slip21 "github.com/anyproto/go-slip21"
    )

    func main(){
        seed, err := hex.DecodeString("c76c4ac4f4e4a00d6b274d5c39c700bb4a7ddc04fbc6f78e85ca75007b5b495f74a9043eeb77bdd53aa6fc3a0e31462270316fa04b8c19114c8798706cd02ac8")
        if err != nil {
            panic(err)
        }
        
        // slip21.Prefix is "m/SLIP-0021"
        node, err := slip21.DeriveForPath(slip21.Prefix + "/Authentication key", seed)
        if err != nil {
            panic(err)
        }
        
        // prints 47194e938ab24cc82bfa25f6486ed54bebe79c40ae2a5a32ea6db294d81861a6
        fmt.Printf("%x\n", node.SymmetricKey())
    }
```


# Licensing

The code in this project is licensed under the MIT License
