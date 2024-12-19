import { AuthenticatedRequest } from "../trpc"

export const doThings = async (req: AuthenticatedRequest, res: Response) => {
  console.log("User Id: ", req.userId)
}