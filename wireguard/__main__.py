from wireguard.backend import backend


def manage_menu():
    while True:
        print("\nWireGuard Installer Menu")
        print("1. Add New Client")
        print("2. List Clients")
        print("3. Exit")

        choice = input("Choose an option: ")

        if choice == '1':
            backend.new_client()
        elif choice == '2':
            backend.list_clients()
        elif choice == '3':
            break
        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    manage_menu()
